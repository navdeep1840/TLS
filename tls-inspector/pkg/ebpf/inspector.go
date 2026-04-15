package ebpf

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
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
	"github.com/emergent/tls-inspector/pkg/ipinfo"
	"github.com/emergent/tls-inspector/pkg/metadata"
	"github.com/emergent/tls-inspector/pkg/netinfo"
	"github.com/emergent/tls-inspector/pkg/output"
)

// alertKey identifies a unique (pid, rule, matchValue) tuple for deduplication.
type alertKey struct {
	pid   uint32
	rule  string
	value string
}

// pidCmdlineEntry caches a process's cmdline to survive after the process exits.
type pidCmdlineEntry struct {
	cmdline    string
	exe        string
	execPath   string // resolved path of the binary (/proc/{pid}/exe)
	scriptPath string // script/file argument for interpreted runtimes
}

// interpreters whose first non-flag argument is the file being executed.
var interpreters = map[string]bool{
	"python": true, "python3": true, "python2": true,
	"node": true, "nodejs": true,
	"ruby": true,
	"php": true, "php8": true, "php7": true,
	"perl": true,
	"bash": true, "sh": true, "zsh": true, "dash": true,
	"java": true,
}

// extractScriptPath parses a cmdline (null-byte-split args joined by space)
// and returns the script/file argument for interpreted runtimes.
// For compiled binaries (curl, wget, etc.) it returns "".
func extractScriptPath(process, cmdline string) string {
	if cmdline == "" {
		return ""
	}
	args := strings.Fields(cmdline)
	if len(args) < 2 {
		return ""
	}
	base := strings.ToLower(filepath.Base(process))
	// Strip version suffix: python3.11 → python3
	for k := range interpreters {
		if strings.HasPrefix(base, k) {
			base = k
			break
		}
	}
	if !interpreters[base] {
		return ""
	}
	// For java, look for -jar flag
	if base == "java" {
		for i, a := range args {
			if a == "-jar" && i+1 < len(args) {
				return args[i+1]
			}
		}
		return ""
	}
	// Skip the interpreter binary itself (args[0]), then skip flags (-v, --flag, -c …)
	for i := 1; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			// -c takes an inline string argument — no script file
			if a == "-c" {
				return ""
			}
			continue
		}
		// First non-flag argument is the script
		return a
	}
	return ""
}

// pidHostEntry caches the HTTP Host header seen for a PID.
// curl/python send headers and body in separate SSL_write calls; the Host
// header lives in the first write, the detection fires on the second.
type pidHostEntry struct {
	host      string
	expiresAt time.Time
}

type TLSInspector struct {
	objs         *ebpf.Collection
	links        []link.Link
	reader       *ringbuf.Reader
	detector     *detector.DetectionEngine
	config       *config.Config
	outputFile   *os.File
	bootOffset   time.Duration          // wall-clock time at boot, for monotonic→wall conversion
	AllTraffic   bool                   // emit non-detection events too
	JSONOutput   bool                   // emit raw JSON instead of structured text
	attachedInos map[uint64]struct{}    // inode dedup: avoid double-attaching symlink targets
	recentAlerts map[alertKey]time.Time // alert dedup: suppress repeated matches within window
	ipClient     *ipinfo.Client         // IP geolocation / threat intel client
	cmdlineCache sync.Map               // map[uint32]pidCmdlineEntry — survives process exit
	hostCache    sync.Map               // map[uint32]pidHostEntry — Host header per PID
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
		ipClient:     ipinfo.New(),
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
	// Phase 1: host filesystem + process maps scan
	for path := range t.discoverAllLibSSLPaths() {
		if err := t.attachToLibrary(path); err != nil {
			log.Printf("Warning: could not attach to %s: %v", path, err)
		}
	}

	// Phase 2: statically-linked TLS binaries (Node.js, etc.)
	t.attachStaticTLSBinaries()

	// Phase 3: target processes currently running — attach to their exact libssl
	t.attachTargetProcessLibSSL()

	if len(t.links) == 0 {
		return errors.New("failed to attach to any TLS library or binary")
	}
	return nil
}

// attachTargetProcessLibSSL scans currently running target processes (curl,
// python3, etc.) and attaches to whatever libssl they have mapped. This is the
// most reliable way to catch processes that use non-standard libssl paths.
func (t *TLSInspector) attachTargetProcessLibSSL() {
	entries, _ := os.ReadDir("/proc")
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		commData, _ := os.ReadFile(fmt.Sprintf("/proc/%s/comm", entry.Name()))
		comm := strings.TrimSpace(string(commData))
		if !t.matchesTarget(comm) {
			continue
		}

		// Pre-populate the cmdline cache while the process is still running.
		// This ensures cmdline is available even if the process exits before
		// the BPF event is processed in userspace.
		if pidNum, err := fmt.Sscanf(entry.Name(), "%d", new(uint32)); pidNum == 1 && err == nil {
			var pid uint32
			fmt.Sscanf(entry.Name(), "%d", &pid)
			if _, cached := t.cmdlineCache.Load(pid); !cached {
				cmdlineRaw, _ := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", entry.Name()))
				if len(cmdlineRaw) > 0 {
					cmdline := strings.TrimSpace(strings.ReplaceAll(string(cmdlineRaw), "\x00", " "))
					execPath, _ := os.Readlink(fmt.Sprintf("/proc/%s/exe", entry.Name()))
					procName := strings.Fields(cmdline)[0]
					t.cmdlineCache.Store(pid, pidCmdlineEntry{
						cmdline:    cmdline,
						execPath:   execPath,
						scriptPath: extractScriptPath(procName, cmdline),
					})
				}
			}
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
			if strings.HasSuffix(libPath, ".so") || strings.Contains(libPath, ".so.") {
				if err := t.attachToLibrary(libPath); err != nil {
					log.Printf("target proc %s libssl %s: %v", comm, libPath, err)
				}
			}
		}
		f.Close()
	}
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
		// Resolve through host root — the exe path from /proc/<pid>/exe is a
		// host absolute path; on container we must access it via /proc/1/root.
		resolved := hostPath(exe)
		if _, err := os.Stat(resolved); err != nil {
			continue
		}
		log.Printf("Attaching SSL probes to static binary: %s (via %s)", exe, resolved)
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
// found via multiple strategies: running process maps, host filesystem scan,
// well-known fallbacks, Homebrew paths, and ldconfig dirs.
func (t *TLSInspector) discoverAllLibSSLPaths() map[string]struct{} {
	found := make(map[string]struct{})

	// 1. Scan every running process's memory maps — picks up libraries already
	//    loaded by long-lived processes (daemons, servers, etc.)
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
			found[libPath] = struct{}{}
		}
		f.Close()
	}

	// 2. Host filesystem scan via /proc/1/root — finds every libssl installed
	//    on the host regardless of which processes are currently running.
	//    Critical for container deployments and for catching curl/python paths
	//    that only load libssl transiently.
	hostRoot := "/proc/1/root"
	hostPatterns := []string{
		// Standard system library dirs
		hostRoot + "/usr/lib/x86_64-linux-gnu/libssl.so*",
		hostRoot + "/usr/lib/aarch64-linux-gnu/libssl.so*",
		hostRoot + "/usr/lib64/libssl.so*",
		hostRoot + "/usr/lib/libssl.so*",
		hostRoot + "/lib/x86_64-linux-gnu/libssl.so*",
		hostRoot + "/lib64/libssl.so*",
		hostRoot + "/usr/local/lib/libssl.so*",
		hostRoot + "/usr/local/lib64/libssl.so*",
		// Linuxbrew (shared install)
		hostRoot + "/home/linuxbrew/.linuxbrew/opt/openssl*/lib/libssl.so*",
		hostRoot + "/home/linuxbrew/.linuxbrew/Cellar/openssl*/*/lib/libssl.so*",
		// pyenv — Python 3.x may bundle its own OpenSSL under ~/.pyenv
		hostRoot + "/home/*/.pyenv/versions/*/lib/libssl.so*",
		hostRoot + "/root/.pyenv/versions/*/lib/libssl.so*",
		// Per-user Linuxbrew
		hostRoot + "/home/*/.linuxbrew/opt/openssl*/lib/libssl.so*",
		// snap-bundled OpenSSL (for snap-packaged curl, python, etc.)
		hostRoot + "/snap/*/current/usr/lib/x86_64-linux-gnu/libssl.so*",
		hostRoot + "/snap/*/*/usr/lib/x86_64-linux-gnu/libssl.so*",
	}
	for _, pattern := range hostPatterns {
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			// Strip the /proc/1/root prefix to get the canonical host path.
			// attachToLibrary will re-resolve via hostPath() when opening.
			hostPath := strings.TrimPrefix(m, hostRoot)
			if hostPath != "" {
				found[hostPath] = struct{}{}
			}
		}
	}

	// 3. ldconfig dirs — covers anything registered with the dynamic linker
	if paths := ldconfigLibSSL(); len(paths) > 0 {
		for _, p := range paths {
			found[p] = struct{}{}
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

// hostPath resolves an absolute filesystem path through the host root.
// When running inside a container with --pid=host, /proc/1/root points to
// the host's root filesystem. Using it ensures we open the *host's* copy of
// a library (correct symbol offsets) rather than the container's copy.
// When running natively, /proc/1/root resolves to the same files as /, so
// the behaviour is identical in both cases.
func hostPath(p string) string {
	candidate := "/proc/1/root" + p
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return p
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
	// Resolve through the host root filesystem so that when running inside a
	// container we open the host's copy of the library (with correct symbol
	// offsets), not the container's copy.
	resolved := hostPath(libPath)

	// Deduplicate by inode so multiple symlinks to the same file only attach once.
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("stat %s: %w", resolved, err)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		ino := st.Ino
		if _, already := t.attachedInos[ino]; already {
			return nil // already attached; silently skip (called frequently by rescan)
		}
		t.attachedInos[ino] = struct{}{}
	}

	ex, err := link.OpenExecutable(resolved)
	if err != nil {
		return fmt.Errorf("opening %s: %w", libPath, err)
	}

	type probeSpec struct {
		symbol   string
		progKey  string
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

	log.Printf("Attached %d probes to %s (via %s)", attached, libPath, resolved)
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

	// Background rescan: every 10 s re-discover libssl paths and attach any
	// that weren't loaded when the inspector started (covers curl, python, java,
	// etc. that may not have been running at startup time).
	go t.periodicRescan(10 * time.Second)

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
		Timestamp:   ts,
		Process:     commStr,
		PID:         raw.PID,
		TID:         raw.TID,
		UID:         raw.UID,
		Library:     "libssl",
		Function:    events.GetFunctionName(raw.FunctionType),
		Direction:   events.GetDirection(raw.FunctionType),
		DataLen:     raw.DataLen,
		ProjectName: t.config.ProjectName,
		Usecase:     t.config.Usecase,
	}

	// Plaintext preview (printable chars only)
	previewLen := raw.DataLen
	if previewLen > 512 {
		previewLen = 512
	}
	event.PlaintextPreview = sanitizePreview(string(raw.Data[:previewLen]))

	// Enrich with process/container metadata.
	// Try live /proc first; fall back to the cmdline cache (populated when we
	// first scanned this process — survives after the process exits).
	if meta, err := metadata.GetProcessMetadata(raw.PID); err == nil && meta.Cmdline != "" {
		event.CommandLine = meta.Cmdline
		event.ContainerID = meta.ContainerID
		event.PodName = meta.PodName
		event.Namespace = meta.Namespace
		// Resolve exec path and script path live while the process still exists
		execPath, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", raw.PID))
		scriptPath := extractScriptPath(event.Process, meta.Cmdline)
		event.ExecPath = execPath
		event.ScriptPath = scriptPath
		// Refresh the cache with fresh data
		t.cmdlineCache.Store(raw.PID, pidCmdlineEntry{
			cmdline:    meta.Cmdline,
			execPath:   execPath,
			scriptPath: scriptPath,
		})
	} else if v, ok := t.cmdlineCache.Load(raw.PID); ok {
		entry := v.(pidCmdlineEntry)
		event.CommandLine = entry.cmdline
		event.ExecPath = entry.execPath
		event.ScriptPath = entry.scriptPath
	}

	// Full TLS plaintext — used for both detection and IP extraction.
	fullData := string(raw.Data[:raw.DataLen])

	// Always index any Host header in this event so future writes by the same
	// PID (e.g. the body write that triggers a detection) can find it.
	if host := extractHTTPHost(fullData); host != "" {
		t.hostCache.Store(raw.PID, pidHostEntry{
			host:      host,
			expiresAt: time.Now().Add(30 * time.Second),
		})
	}

	// Enrich with remote IP geolocation.
	// Priority: 1) /proc TCP table  2) Host header in this event
	//           3) cached Host header from an earlier write by the same PID
	remoteIPs := netinfo.GetRemoteIPs(raw.PID)
	if len(remoteIPs) == 0 {
		host := extractHTTPHost(fullData)
		if host == "" {
			if v, ok := t.hostCache.Load(raw.PID); ok {
				e := v.(pidHostEntry)
				if time.Now().Before(e.expiresAt) {
					host = e.host
				}
			}
		}
		if host != "" {
			if addrs, err := net.LookupHost(host); err == nil {
				for _, addr := range addrs {
					if ip := net.ParseIP(addr); ip != nil && isPublicIP(ip) {
						remoteIPs = append(remoteIPs, addr)
					}
				}
			}
		}
	}
	if len(remoteIPs) > 0 {
		event.RemoteIPs = remoteIPs
		for _, ip := range remoteIPs {
			if info, err := t.ipClient.Lookup(ip); err == nil {
				event.IPDetails = append(event.IPDetails, info)
			} else {
				log.Printf("ipinfo lookup %s: %v", ip, err)
			}
		}
	}

	// Run detection rules
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

	// POST to remote server if configured (detections only, non-blocking)
	if t.config.ServerURL != "" && len(detections) > 0 {
		go t.postEvent(event)
	}
}

var httpClient = &http.Client{Timeout: 5 * time.Second}

func (t *TLSInspector) postEvent(event *events.TLSEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", t.config.ServerURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("POST %s: build request: %v", t.config.ServerURL, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if t.config.APIKey != "" {
		req.Header.Set("x-api-key", t.config.APIKey)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("POST %s: %v", t.config.ServerURL, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		log.Printf("POST %s: server returned %s", t.config.ServerURL, resp.Status)
	}
}

// periodicRescan runs in a goroutine and re-discovers TLS library paths every
// interval, attaching uprobes to any new paths not seen at startup.
// This is critical when running inside a container: at startup, short-lived
// processes like curl or python may not yet be in /proc/*/maps.
func (t *TLSInspector) periodicRescan(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		for path := range t.discoverAllLibSSLPaths() {
			if err := t.attachToLibrary(path); err != nil {
				log.Printf("rescan: %s: %v", path, err)
			}
		}
		t.attachStaticTLSBinaries()
		t.attachTargetProcessLibSSL()
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

// extractHTTPHost parses the HTTP Host header from raw TLS plaintext.
// Works for both request headers ("Host: example.com") and in request lines.
func extractHTTPHost(data string) string {
	for _, line := range strings.SplitN(data, "\n", 64) {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host := strings.TrimSpace(line[5:])
			// Strip port if present (and not an IPv6 literal)
			if !strings.HasPrefix(host, "[") {
				if idx := strings.LastIndex(host, ":"); idx > 0 {
					host = host[:idx]
				}
			}
			return host
		}
	}
	return ""
}

// isPublicIP reports whether ip is a globally routable (non-private) address.
func isPublicIP(ip net.IP) bool {
	private := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10",
		"169.254.0.0/16", "0.0.0.0/8",
	}
	for _, cidr := range private {
		_, block, _ := net.ParseCIDR(cidr)
		if block != nil && block.Contains(ip) {
			return false
		}
	}
	return true
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
