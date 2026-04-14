package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/emergent/tls-inspector/pkg/config"
	"github.com/emergent/tls-inspector/pkg/detector"
	"github.com/emergent/tls-inspector/pkg/events"
	"github.com/emergent/tls-inspector/pkg/metadata"
)

type TLSInspector struct {
	objs       *ebpf.Collection
	links      []link.Link
	reader     *ringbuf.Reader
	detector   *detector.DetectionEngine
	config     *config.Config
	outputFile *os.File
}

func NewTLSInspector(cfg *config.Config, det *detector.DetectionEngine) (*TLSInspector, error) {
	// Remove memory lock limits
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock: %w", err)
	}

	return &TLSInspector{
		detector: det,
		config:   cfg,
	}, nil
}

func (t *TLSInspector) Load(objPath string) error {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return fmt.Errorf("loading eBPF spec: %w", err)
	}

	objs := &ebpf.Collection{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return fmt.Errorf("loading eBPF objects: %w", err)
	}

	t.objs = objs
	return nil
}

func (t *TLSInspector) AttachToProcesses() error {
	processes, err := findTargetProcesses(t.config.IncludeProcesses)
	if err != nil {
		return err
	}

	if len(processes) == 0 {
		log.Println("No target processes found, will attach to system-wide OpenSSL")
		return t.attachSystemWide()
	}

	log.Printf("Found %d target processes\n", len(processes))

	for _, proc := range processes {
		if err := t.attachToProcess(proc); err != nil {
			log.Printf("Warning: failed to attach to PID %d: %v\n", proc.PID, err)
			continue
		}
		log.Printf("Attached to PID %d (%s)\n", proc.PID, proc.Name)
	}

	if len(t.links) == 0 {
		return errors.New("failed to attach to any process")
	}

	return nil
}

func (t *TLSInspector) attachSystemWide() error {
	// Try common OpenSSL library paths
	libraries := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/usr/lib64/libssl.so.3",
		"/usr/lib64/libssl.so.1.1",
		"/usr/lib/libssl.so",
	}

	for _, libPath := range libraries {
		if _, err := os.Stat(libPath); err == nil {
			log.Printf("Attaching to system library: %s\n", libPath)
			return t.attachToLibrary(libPath)
		}
	}

	return errors.New("no OpenSSL library found")
}

func (t *TLSInspector) attachToProcess(proc ProcessInfo) error {
	libPath, err := metadata.FindLibraryPath(proc.PID, "libssl")
	if err != nil {
		return err
	}

	return t.attachToLibrary(libPath)
}

func (t *TLSInspector) attachToLibrary(libPath string) error {
	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		return fmt.Errorf("opening executable %s: %w", libPath, err)
	}

	// Attach SSL_write
	if prog := t.objs.Programs["probe_ssl_write"]; prog != nil {
		l, err := ex.Uprobe("SSL_write", prog, nil)
		if err == nil {
			t.links = append(t.links, l)
		}
	}

	// Attach SSL_read
	if prog := t.objs.Programs["probe_ssl_read"]; prog != nil {
		l, err := ex.Uprobe("SSL_read", prog, nil)
		if err == nil {
			t.links = append(t.links, l)
		}
	}

	if prog := t.objs.Programs["probe_ssl_read_ret"]; prog != nil {
		l, err := ex.Uretprobe("SSL_read", prog, nil)
		if err == nil {
			t.links = append(t.links, l)
		}
	}

	// Attach SSL_write_ex
	if prog := t.objs.Programs["probe_ssl_write_ex"]; prog != nil {
		l, err := ex.Uprobe("SSL_write_ex", prog, nil)
		if err == nil {
			t.links = append(t.links, l)
		}
	}

	// Attach SSL_read_ex
	if prog := t.objs.Programs["probe_ssl_read_ex_entry"]; prog != nil {
		l, err := ex.Uprobe("SSL_read_ex", prog, nil)
		if err == nil {
			t.links = append(t.links, l)
		}
	}

	if prog := t.objs.Programs["probe_ssl_read_ex_ret"]; prog != nil {
		l, err := ex.Uretprobe("SSL_read_ex", prog, nil)
		if err == nil {
			t.links = append(t.links, l)
		}
	}

	return nil
}

func (t *TLSInspector) Start() error {
	// Open output file if configured
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

	// Open ring buffer reader
	rd, err := ringbuf.NewReader(t.objs.Maps["events"])
	if err != nil {
		return fmt.Errorf("opening ringbuf reader: %w", err)
	}
	t.reader = rd

	log.Println("TLS Inspector started, monitoring traffic...")

	// Handle signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		log.Println("\nShutting down...")
		t.Close()
		os.Exit(0)
	}()

	// Process events
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}

		var rawEvent events.RawTLSEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &rawEvent); err != nil {
			continue
		}

		t.processEvent(&rawEvent)
	}
}

func (t *TLSInspector) processEvent(raw *events.RawTLSEvent) {
	// Convert to structured event
	event := &events.TLSEvent{
		Timestamp: time.Unix(0, int64(raw.Timestamp)),
		Process:   strings.TrimRight(string(raw.Comm[:]), "\x00"),
		PID:       raw.PID,
		TID:       raw.TID,
		UID:       raw.UID,
		Library:   "libssl",
		Function:  events.GetFunctionName(raw.FunctionType),
		Direction: events.GetDirection(raw.FunctionType),
		DataLen:   raw.DataLen,
	}

	// Get plaintext preview
	if raw.DataLen > 0 {
		previewLen := raw.DataLen
		if previewLen > 200 {
			previewLen = 200
		}
		event.PlaintextPreview = sanitizePreview(string(raw.Data[:previewLen]))
	}

	// Enrich with metadata
	if meta, err := metadata.GetProcessMetadata(raw.PID); err == nil {
		event.CommandLine = meta.Cmdline
		event.ContainerID = meta.ContainerID
		event.PodName = meta.PodName
		event.Namespace = meta.Namespace
	}

	// Run detections
	fullData := string(raw.Data[:raw.DataLen])
	detections := t.detector.Analyze(fullData)
	if len(detections) > 0 {
		for _, det := range detections {
			event.Detections = append(event.Detections, det.RuleName)
		}
		event.Severity = string(detector.GetHighestSeverity(detections))
	}

	// Output event
	t.outputEvent(event)
}

func (t *TLSInspector) outputEvent(event *events.TLSEvent) {
	jsonData, err := event.ToJSON()
	if err != nil {
		return
	}

	// Output to stdout
	if t.config.Output == "stdout" || t.config.Output == "both" {
		fmt.Println(string(jsonData))
	}

	// Output to file
	if (t.config.Output == "file" || t.config.Output == "both") && t.outputFile != nil {
		t.outputFile.Write(jsonData)
		t.outputFile.WriteString("\n")
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
	// Remove non-printable characters
	var result strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 || r == '\n' || r == '\t' {
			result.WriteRune(r)
		} else {
			result.WriteRune('.')
		}
	}
	return result.String()
}
