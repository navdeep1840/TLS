package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/emergent/tls-inspector/pkg/config"
	"github.com/emergent/tls-inspector/pkg/detector"
	"github.com/emergent/tls-inspector/pkg/ebpf"
)

var (
	configPath string
	ebpfObj    string
	allTraffic bool
	jsonOutput bool
)

var rootCmd = &cobra.Command{
	Use:   "tls-inspector",
	Short: "eBPF-based TLS plaintext inspection agent",
	Long:  `A production-quality eBPF agent for monitoring TLS traffic from curl and Python applications.`,
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the TLS inspector",
	RunE:  runInspector,
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show inspector status",
	Run:   showStatus,
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage detection rules",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all detection rules",
	RunE:  listRules,
}

var rulesTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test detection rules against sample data",
	RunE:  testRules,
}

func init() {
	runCmd.Flags().StringVarP(&configPath, "config", "c", "./configs/config.yaml", "Path to config file")
	runCmd.Flags().StringVarP(&ebpfObj, "ebpf-obj", "e", "./bpf/tls_probe.o", "Path to compiled eBPF object file")
	runCmd.Flags().BoolVar(&allTraffic, "all-traffic", false, "Print all captured traffic, not just rule matches")
	runCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output raw JSON instead of structured text")

	rulesListCmd.Flags().StringVarP(&configPath, "config", "c", "./configs/config.yaml", "Path to config file")
	rulesTestCmd.Flags().StringVarP(&configPath, "config", "c", "./configs/config.yaml", "Path to config file")

	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesTestCmd)

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(rulesCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runInspector(cmd *cobra.Command, args []string) error {
	// Load config
	var cfg *config.Config
	var err error

	if _, err := os.Stat(configPath); err == nil {
		cfg, err = config.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
	} else {
		log.Println("Config file not found, using defaults")
		cfg = config.DefaultConfig()
	}

	log.Printf("Config: capture_bytes=%d, rules=%s, output=%s\n",
		cfg.CaptureBytes, cfg.RulesPath, cfg.Output)

	// Load detection rules
	det, err := detector.NewDetectionEngine(cfg.RulesPath)
	if err != nil {
		return fmt.Errorf("loading detection rules: %w", err)
	}
	log.Printf("Loaded %d detection rules\n", len(det.GetRules()))

	// Create inspector
	inspector, err := ebpf.NewTLSInspector(cfg, det)
	if err != nil {
		return fmt.Errorf("creating inspector: %w", err)
	}
	defer inspector.Close()
	inspector.AllTraffic = allTraffic
	inspector.JSONOutput = jsonOutput

	// Load eBPF program
	log.Printf("Loading eBPF program from %s\n", ebpfObj)
	if err := inspector.Load(ebpfObj); err != nil {
		return fmt.Errorf("loading eBPF program: %w", err)
	}

	// Attach to processes
	if err := inspector.AttachToProcesses(); err != nil {
		return fmt.Errorf("attaching to processes: %w", err)
	}

	// Start monitoring
	return inspector.Start()
}

func showStatus(cmd *cobra.Command, args []string) {
	processes, err := ebpf.ListRunningProcesses()
	if err != nil {
		log.Fatalf("Error listing processes: %v", err)
	}

	targetNames := []string{"curl", "python"}
	fmt.Println("Target processes:")
	for _, proc := range processes {
		for _, target := range targetNames {
			if proc.Name == target {
				fmt.Printf("  PID %d: %s (%s)\n", proc.PID, proc.Name, proc.Cmdline)
			}
		}
	}
}

func listRules(cmd *cobra.Command, args []string) error {
	var cfg *config.Config
	var err error

	if _, err := os.Stat(configPath); err == nil {
		cfg, err = config.LoadConfig(configPath)
		if err != nil {
			return err
		}
	} else {
		cfg = config.DefaultConfig()
	}

	det, err := detector.NewDetectionEngine(cfg.RulesPath)
	if err != nil {
		return err
	}

	fmt.Println("Detection Rules:")
	fmt.Println("=", "\n")
	for _, rule := range det.GetRules() {
		status := "disabled"
		if rule.Enabled {
			status = "enabled"
		}
		fmt.Printf("[%s] %s - %s\n", status, rule.ID, rule.Name)
		fmt.Printf("  Severity: %s\n", rule.Severity)
		fmt.Printf("  Description: %s\n", rule.Description)
		fmt.Println()
	}

	return nil
}

func testRules(cmd *cobra.Command, args []string) error {
	var cfg *config.Config
	var err error

	if _, err := os.Stat(configPath); err == nil {
		cfg, err = config.LoadConfig(configPath)
		if err != nil {
			return err
		}
	} else {
		cfg = config.DefaultConfig()
	}

	det, err := detector.NewDetectionEngine(cfg.RulesPath)
	if err != nil {
		return err
	}

	// Test samples
	testSamples := []string{
		"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"github_pat_11AAAAAA_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789",
		"password=MySecretPassword123",
		"api_key=sk-1234567890abcdef",
	}

	fmt.Println("Testing detection rules:\n")

	for i, sample := range testSamples {
		fmt.Printf("Sample %d: %s\n", i+1, sample)
		detections := det.Analyze(sample)
		if len(detections) > 0 {
			for _, det := range detections {
				fmt.Printf("  ✓ Detected: %s (severity: %s)\n", det.RuleName, det.Severity)
			}
		} else {
			fmt.Println("  ✗ No detections")
		}
		fmt.Println()
	}

	return nil
}
