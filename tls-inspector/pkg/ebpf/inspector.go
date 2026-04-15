package ebpf

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/emergent/tls-inspector/pkg/config"
	"github.com/emergent/tls-inspector/pkg/detector"
	"github.com/emergent/tls-inspector/pkg/events"
	"github.com/emergent/tls-inspector/pkg/metadata"
	"github.com/emergent/tls-inspector/pkg/output"
)

// alertKey identifies a unique (pid, rule, matchValue) tuple for deduplication.
type alertKey struct {
	pid   uint32
	rule  string
	value string
}

type TLSInspector struct {
	objs         *ebpf.Collection
	links        []link.Link
	reader       *ringbuf.Reader
	detector     *detector.DetectionEngine
	config       *config.Config
	outputFile   *os.File
	bootOffset   time.Duration      // wall-clock time at boot, for monotonic→wall conversion
	AllTraffic   bool               // emit non-detection events too
	JSONOutput   bool               // emit raw JSON instead of structured text
	attachedInos map[uint64]struct{} // inode dedup: avoid double-attaching symlink targets
	recentAlerts map[alertKey]time.Time // alert dedup: suppress repeated matches within window
}

func NewTLSInspector(cfg *config.Config, det *detector.DetectionEngine) (*TLSInspector, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}
	return &TLSInspector{
		detector:     det,
		config:       cfg,
		bootOffset:   bootTimeOffset(),
		attachedInos: make(map[uint64]struct{}),
		recentAlerts: make(map[alertKey]time.Time),
	}, nil
}

// bootTimeOffset returns the wall-clock time at system boot by reading
// /proc/stat's btime field, so we can convert monotonic BPF ns to real time.
func bootTimeOffset() time.Duration {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		var btime int64
		fmt.Sscanf(line, "btime %d", &btime)
		return time.Duration(btime) * time.Second
	}
	return 0
}

func (t *TLSInspector) Load(objPath string) error {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("loading eBPF spec: %w", err)
	}

	var opts ebpf.CollectionOptions
	if kernelSpec, kerr := btf.LoadKernelSpec(); kerr == nil {
		opts.Programs.KernelTypes = kernelSpec
	} else {
		log.Printf("Warning: could not load kernel BTF: %v", kerr)
	}

	objs, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	log.Printf("Loaded %d eBPF programs", len(spec.Programs))
	for name := range spec.Programs {
		log.Printf("  - %s", name)
	}

	t.objs = objs
	return nil
}

// AttachToProcesses discovers all unique libssl.so paths across all running
// processes and attaches uprobes to each. Also attaches directly to binaries
// that bundle OpenSSL statically (e.g. Node.js built via nvm).
func (t *TLSInspector) AttachToProcesses() error {
	// Phase 1: shared libssl.so paths (catches curl, python, etc.)
	for path := range t.discoverAllLibSSLPaths() {
		if err := t.attachToLibrary(path); err != nil {
			log.Printf("Warning: could not attach to %s: %v", path, err)
		}
	}

	// Phase 2: statically-linked TLS binaries (Node.js, etc.)
	t.attachStaticTLSBinaries()

	if len(t.links) == 0 {
		return errors.New("failed to attach to any TLS library or binary")
	}
	return nil
}

// attachStaticTLSBinaries scans for node/nodejs processes and nvm-installed
// node binaries that bundle OpenSSL statically and attaches SSL uprobes directly
// to the binary executable.
func (t *TLSInspector) attachStaticTLSBinaries() {
	candidates := make(map[string]struct{}) // exe paths to try

	// 1. Currently running node processes
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		commData, err := os.ReadFile(fmt.Sprintf("/proc/%s/comm", entry.Name()))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commData))
		if !strings.Contains(strings.ToLower(comm), "node") {
			continue
		}
		// Only attach if the process has no shared libssl in its maps
		if processHasSharedLibSSL(entry.Name()) {
			continue // already covered by Phase 1
		}
		exe, err := os.Readlink(fmt.Sprintf("/proc/%s/exe", entry.Name()))
		if err == nil && exe != "" {
			candidates[exe] = struct{}{}
		}
	}

	// 2. Probe common nvm/nodenv/system node paths even if not running yet
	nvmGlobs := []string{
		os.Getenv("HOME") + "/.nvm/versions/node/*/bin/node",
		"/usr/local/bin/node",
		"/usr/bin/node",
		"/home/linuxbrew/.linuxbrew/bin/node",
	}
	for _, pattern := range nvmGlobs {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			for _, m := range matches {
				candidates[m] = struct{}{}
			}
		}
	}

	for exe := range candidates {
		if _, err := os.Stat(exe); err != nil {
			continue
		}
		log.Printf("Attaching SSL probes to static binary: %s", exe)
		if err := t.attachToLibrary(exe); err != nil {
			log.Printf("Warning: could not attach to %s: %v", exe, err)
		}
	}
}

// processHasSharedLibSSL returns true if the process has a libssl.so mapped.
func processHasSharedLibSSL(pid string) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%s/maps", pid))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.Contains(sc.Text(), "libssl") {
			return true
		}
	}
	return false
}

// discoverAllLibSSLPaths returns a deduplicated set of resolved libssl.so paths
// found in all running process maps plus well-known locations.
func (t *TLSInspector) discoverAllLibSSLPaths() map[string]struct{} {
	found := make(map[string]struct{})

	// 1. Scan every process's memory maps
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		mapsPath := fmt.Sprintf("/proc/%s/maps", entry.Name())
		f, err := os.Open(mapsPath)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.Contains(line, "libssl") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			libPath := fields[5]
			if !strings.HasSuffix(libPath, ".so") &&
				!strings.Contains(libPath, ".so.") {
				continue
			}
			// Resolve symlinks so we only attach once per physical file
			if real, err := resolveRealPath(libPath); err == nil {
				found[real] = struct{}{}
			} else {
				found[libPath] = struct{}{}
			}
		}
		f.Close()
	}

	// 2. Well-known fallback paths (catches paths not yet mapped by any proc)
	fallbacks := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib64/libssl.so.3",
		"/usr/lib64/libssl.so.1.1",
		"/usr/lib/libssl.so",
		"/lib/x86_64-linux-gnu/libssl.so.3",
	}
	for _, p := range fallbacks {
		if _, err := os.Stat(p); err == nil {
			addPath(found, p)
		}
	}

	// 3. Glob for Homebrew / Linuxbrew OpenSSL (any version, any user prefix)
	brewGlobs := []string{
		"/home/linuxbrew/.linuxbrew/opt/openssl*/lib/libssl.so*",
		"/home/linuxbrew/.linuxbrew/Cellar/openssl*/*/lib/libssl.so*",
		"/home/*/.linuxbrew/opt/openssl*/lib/libssl.so*",
		"/usr/local/opt/openssl*/lib/libssl.so*", // macOS Homebrew (just in case)
		"/opt/homebrew/opt/openssl*/lib/libssl.so*",
	}
	for _, pattern := range brewGlobs {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			addPath(found, m)
		}
	}

	// 4. ldconfig cache — covers anything registered with the dynamic linker
	if paths := ldconfigLibSSL(); len(paths) > 0 {
		for _, p := range paths {
			addPath(found, p)
		}
	}

	for p := range found {
		log.Printf("Discovered libssl: %s", p)
	}
	return found
}

func resolveRealPath(p string) (string, error) {
	return os.Readlink(p) // if not a symlink, returns error; caller falls back to p
}

// addPath resolves symlinks and adds the real path to the set.
func addPath(m map[string]struct{}, p string) {
	if real, err := os.Readlink(p); err == nil {
		// Readlink gives a relative path for relative symlinks; resolve it
		if !filepath.IsAbs(real) {
			real = filepath.Join(filepath.Dir(p), real)
		}
		m[real] = struct{}{}
	} else {
		m[p] = struct{}{}
	}
}

// ldconfigLibSSL parses /etc/ld.so.cache via ldconfig -p to find all libssl paths.
func ldconfigLibSSL() []string {
	// We can't exec ldconfig easily in BPF context, so parse /etc/ld.so.conf.d
	// and scan common library cache paths instead.
	var found []string
	dirs := []string{"/etc/ld.so.conf.d"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				// line is a directory; glob for libssl in it
				matches, _ := filepath.Glob(filepath.Join(line, "libssl.so*"))
				found = append(found, matches...)
			}
		}
	}
	return found
}

func (t *TLSInspector) attachToLibrary(libPath string) error {
	// Deduplicate by inode so multiple symlinks to the same file only attach once.
	info, err := os.Stat(libPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", libPath, err)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		ino := st.Ino
		if _, already := t.attachedInos[ino]; already {
			log.Printf("Skipping %s (same inode as already-attached library)", libPath)
			return nil
		}
		t.attachedInos[ino] = struct{}{}
	}

	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		return fmt.Errorf("opening %s: %w", libPath, err)
	}

	type probeSpec struct {
		symbol  string
		progKey string
		retProbe bool
	}
	probes := []probeSpec{
		{"SSL_write", "probe_ssl_write", false},
		{"SSL_read", "probe_ssl_read_entry", false},
		{"SSL_read", "probe_ssl_read_ret", true},
		{"SSL_write_ex", "probe_ssl_write_ex", false},
		{"SSL_read_ex", "probe_ssl_read_ex_entry", false},
		{"SSL_read_ex", "probe_ssl_read_ex_ret", true},
	}

	attached := 0
	for _, ps := range probes {
		prog := t.objs.Programs[ps.progKey]
		if prog == nil {
			continue
		}
		var l link.Link
		var lerr error
		if ps.retProbe {
			l, lerr = ex.Uretprobe(ps.symbol, prog, nil)
		} else {
			l, lerr = ex.Uprobe(ps.symbol, prog, nil)
		}
		if lerr != nil {
			log.Printf("Warning: %s %s on %s: %v", ps.progKey, ps.symbol, libPath, lerr)
			continue
		}
		t.links = append(t.links, l)
		attached++
	}

	log.Printf("Attached %d probes to %s", attached, libPath)
	return nil
}

func (t *TLSInspector) Start() error {
	if t.config.Output == "file" || t.config.Output == "both" {
		if t.config.OutputFile == "" {
			t.config.OutputFile = "tls-events.json"
		}
		f, err := os.OpenFile(t.config.OutputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("opening output file: %w", err)
		}
		t.outputFile = f
	}

	rd, err := ringbuf.NewReader(t.objs.Maps["events"])
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	t.reader = rd

	log.Println("TLS Inspector started, monitoring traffic...")
	log.Printf("Filtering for processes: %v", t.config.IncludeProcesses)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("\nShutting down...")
		t.Close()
		os.Exit(0)
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}

		var raw events.RawTLSEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		t.processEvent(&raw)
	}
}

// matchesTarget returns true if the process comm matches any of the configured
// target names. An empty include list means "match everything".
func (t *TLSInspector) matchesTarget(comm string) bool {
	if len(t.config.IncludeProcesses) == 0 {
		return true
	}
	lc := strings.ToLower(comm)
	for _, target := range t.config.IncludeProcesses {
		if strings.Contains(lc, strings.ToLower(target)) {
			return true
		}
	}
	return false
}

func (t *TLSInspector) processEvent(raw *events.RawTLSEvent) {
	// Skip events with no captured data
	if raw.DataLen == 0 {
		return
	}

	// Decode process name: null-terminated, trim all null bytes
	commStr := strings.Trim(string(raw.Comm[:]), "\x00")

	// Filter by configured target process names
	if !t.matchesTarget(commStr) {
		return
	}

	// Convert monotonic BPF ns-since-boot to wall-clock time.
	// bootOffset holds the boot epoch in nanoseconds; add the monotonic offset.
	var ts time.Time
	if raw.Timestamp > 0 && t.bootOffset > 0 {
		ts = time.Unix(0, int64(t.bootOffset)+int64(raw.Timestamp))
	} else {
		ts = time.Now()
	}

	event := &events.TLSEvent{
		Timestamp: ts,
		Process:   commStr,
		PID:       raw.PID,
		TID:       raw.TID,
		UID:       raw.UID,
		Library:   "libssl",
		Function:  events.GetFunctionName(raw.FunctionType),
		Direction: events.GetDirection(raw.FunctionType),
		DataLen:   raw.DataLen,
	}

	// Plaintext preview (printable chars only)
	previewLen := raw.DataLen
	if previewLen > 512 {
		previewLen = 512
	}
	event.PlaintextPreview = sanitizePreview(string(raw.Data[:previewLen]))

	// Enrich with process/container metadata
	if meta, err := metadata.GetProcessMetadata(raw.PID); err == nil {
		event.CommandLine = meta.Cmdline
		event.ContainerID = meta.ContainerID
		event.PodName = meta.PodName
		event.Namespace = meta.Namespace
	}

	// Run detection rules
	fullData := string(raw.Data[:raw.DataLen])
	detections := t.detector.Analyze(fullData)
	if len(detections) > 0 {
		// Deduplicate: drop matches we've already alerted on for this PID within 10s
		const dedupWindow = 10 * time.Second
		now := time.Now()
		var fresh []detector.Detection
		for _, d := range detections {
			for _, m := range d.Matches {
				k := alertKey{pid: raw.PID, rule: d.RuleID, value: m.Value}
				if last, seen := t.recentAlerts[k]; seen && now.Sub(last) < dedupWindow {
					continue
				}
				t.recentAlerts[k] = now
				fresh = append(fresh, d)
				break // one match is enough to include the detection
			}
		}
		detections = fresh

		for _, d := range detections {
			event.Detections = append(event.Detections, d.RuleName)
		}
		if len(detections) > 0 {
			event.Severity = string(detector.GetHighestSeverity(detections))
		}
	}

	t.outputEvent(event, detections)
}

func (t *TLSInspector) outputEvent(event *events.TLSEvent, detections []detector.Detection) {
	toStdout := t.config.Output == "stdout" || t.config.Output == "both"
	toFile := (t.config.Output == "file" || t.config.Output == "both") && t.outputFile != nil

	if t.JSONOutput {
		// Machine-readable JSON (always includes all fields)
		jsonData, err := json.Marshal(event)
		if err != nil {
			return
		}
		if toStdout {
			fmt.Println(string(jsonData))
		}
		if toFile {
			t.outputFile.Write(jsonData)
			t.outputFile.WriteString("\n")
		}
		return
	}

	// Structured human-readable output
	if len(detections) > 0 {
		if toStdout {
			output.PrintAlert(event, detections)
		}
	} else if t.AllTraffic {
		if toStdout {
			output.PrintTraffic(event)
		}
	}

	// Always write JSON to file for machine consumption
	if toFile {
		jsonData, err := json.Marshal(event)
		if err == nil {
			t.outputFile.Write(jsonData)
			t.outputFile.WriteString("\n")
		}
	}
}

func (t *TLSInspector) Close() error {
	if t.reader != nil {
		t.reader.Close()
	}
	for _, l := range t.links {
		l.Close()
	}
	if t.objs != nil {
		t.objs.Close()
	}
	if t.outputFile != nil {
		t.outputFile.Close()
	}
	return nil
}

func sanitizePreview(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 32 && r < 127) || r == '\n' || r == '\r' || r == '\t' {
			b.WriteRune(r)
		} else {
			b.WriteRune('.')
		}
	}
	return b.String()
}
