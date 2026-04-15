package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	CaptureBytes     int      `yaml:"capture_bytes"`
	RulesPath        string   `yaml:"rules_path"`
	Output           string   `yaml:"output"`
	OutputFile       string   `yaml:"output_file,omitempty"`
	IncludeProcesses []string `yaml:"include_processes"`
	LogLevel         string   `yaml:"log_level"`
	BufferSize       int      `yaml:"buffer_size"`
	ServerURL        string   `yaml:"server_url,omitempty"`
	APIKey           string   `yaml:"api_key,omitempty"`
	ProjectName      string   `yaml:"project_name,omitempty"`
	Usecase          string   `yaml:"usecase,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Set defaults
	if cfg.CaptureBytes == 0 {
		cfg.CaptureBytes = 4096
	}
	if cfg.RulesPath == "" {
		cfg.RulesPath = "./rules/default.yaml"
	}
	if cfg.Output == "" {
		cfg.Output = "stdout"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 256 * 1024
	}

	return &cfg, nil
}

func DefaultConfig() *Config {
	return &Config{
		CaptureBytes:     4096,
		RulesPath:        "./rules/default.yaml",
		Output:           "stdout",
		IncludeProcesses: []string{"curl", "python", "python3", "node", "nodejs", "wget", "java", "ruby", "go", "php", "openssl", "httpie", "http"},
		LogLevel:         "info",
		BufferSize:       256 * 1024,
	}
}
