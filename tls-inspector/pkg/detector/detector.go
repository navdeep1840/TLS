package detector

import (
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Rule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    Severity `yaml:"severity"`
	Patterns    []string `yaml:"patterns"`
	Regex       []string `yaml:"regex,omitempty"`
	Keywords    []string `yaml:"keywords,omitempty"`
	Enabled     bool     `yaml:"enabled"`

	compiledRegex []*regexp.Regexp
}

type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

type DetectionEngine struct {
	rules []Rule
}

type Detection struct {
	RuleID   string
	RuleName string
	Severity Severity
	Matches  []string
}

func NewDetectionEngine(rulesPath string) (*DetectionEngine, error) {
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, err
	}

	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return nil, err
	}

	// Compile regex patterns
	for i := range ruleSet.Rules {
		for _, pattern := range ruleSet.Rules[i].Regex {
			re, err := regexp.Compile(pattern)
			if err == nil {
				ruleSet.Rules[i].compiledRegex = append(ruleSet.Rules[i].compiledRegex, re)
			}
		}
	}

	return &DetectionEngine{
		rules: ruleSet.Rules,
	}, nil
}

func (de *DetectionEngine) Analyze(data string) []Detection {
	var detections []Detection
	dataLower := strings.ToLower(data)

	for _, rule := range de.rules {
		if !rule.Enabled {
			continue
		}

		var matches []string

		// Check keywords
		for _, keyword := range rule.Keywords {
			if strings.Contains(dataLower, strings.ToLower(keyword)) {
				matches = append(matches, keyword)
			}
		}

		// Check regex patterns
		for _, re := range rule.compiledRegex {
			if match := re.FindString(data); match != "" {
				// Mask sensitive data in match
				masked := maskSensitive(match)
				matches = append(matches, masked)
			}
		}

		// Check simple patterns (substring match)
		for _, pattern := range rule.Patterns {
			if strings.Contains(data, pattern) {
				matches = append(matches, pattern)
			}
		}

		if len(matches) > 0 {
			detections = append(detections, Detection{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Severity: rule.Severity,
				Matches:  matches,
			})
		}
	}

	return detections
}

func (de *DetectionEngine) GetRules() []Rule {
	return de.rules
}

func maskSensitive(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

func GetHighestSeverity(detections []Detection) Severity {
	if len(detections) == 0 {
		return ""
	}

	severityOrder := map[Severity]int{
		SeverityCritical: 4,
		SeverityHigh:     3,
		SeverityMedium:   2,
		SeverityLow:      1,
	}

	highest := SeverityLow
	highestVal := 0

	for _, det := range detections {
		if val, ok := severityOrder[det.Severity]; ok && val > highestVal {
			highest = det.Severity
			highestVal = val
		}
	}

	return highest
}
