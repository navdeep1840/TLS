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

// Match holds one individual finding within a Detection.
type Match struct {
	Type    string // "regex", "keyword", "pattern"
	Pattern string // the rule pattern / keyword that fired
	Value   string // the actual text that matched (shown to user)
	Context string // ±60 chars of surrounding plaintext
}

// Detection is one rule that fired against the payload.
type Detection struct {
	RuleID   string
	RuleName string
	Severity Severity
	Matches  []Match
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

	for i := range ruleSet.Rules {
		for _, pattern := range ruleSet.Rules[i].Regex {
			re, err := regexp.Compile(pattern)
			if err == nil {
				ruleSet.Rules[i].compiledRegex = append(ruleSet.Rules[i].compiledRegex, re)
			}
		}
	}

	return &DetectionEngine{rules: ruleSet.Rules}, nil
}

func (de *DetectionEngine) Analyze(data string) []Detection {
	var detections []Detection
	dataLower := strings.ToLower(data)

	for _, rule := range de.rules {
		if !rule.Enabled {
			continue
		}

		var matches []Match

		// Regex matches — capture the actual matched value and context
		for _, re := range rule.compiledRegex {
			loc := re.FindStringIndex(data)
			if loc == nil {
				continue
			}
			value := data[loc[0]:loc[1]]
			matches = append(matches, Match{
				Type:    "regex",
				Pattern: re.String(),
				Value:   value,
				Context: extractContext(data, loc[0], loc[1]),
			})
		}

		// Keyword matches
		for _, kw := range rule.Keywords {
			idx := strings.Index(dataLower, strings.ToLower(kw))
			if idx < 0 {
				continue
			}
			matches = append(matches, Match{
				Type:    "keyword",
				Pattern: kw,
				Value:   data[idx : min(idx+len(kw)+40, len(data))],
				Context: extractContext(data, idx, idx+len(kw)),
			})
		}

		// Literal pattern matches
		for _, pat := range rule.Patterns {
			idx := strings.Index(data, pat)
			if idx < 0 {
				continue
			}
			matches = append(matches, Match{
				Type:    "pattern",
				Pattern: pat,
				Value:   pat,
				Context: extractContext(data, idx, idx+len(pat)),
			})
		}

		if len(matches) > 0 {
			// Deduplicate matches by value
			seen := map[string]bool{}
			var deduped []Match
			for _, m := range matches {
				if !seen[m.Value] {
					seen[m.Value] = true
					deduped = append(deduped, m)
				}
			}
			detections = append(detections, Detection{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Severity: rule.Severity,
				Matches:  deduped,
			})
		}
	}

	return detections
}

// extractContext returns ±60 printable characters around [start, end) in data.
func extractContext(data string, start, end int) string {
	const window = 60
	lo := start - window
	if lo < 0 {
		lo = 0
	}
	hi := end + window
	if hi > len(data) {
		hi = len(data)
	}
	ctx := sanitize(data[lo:hi])
	if lo > 0 {
		ctx = "…" + ctx
	}
	if hi < len(data) {
		ctx = ctx + "…"
	}
	return ctx
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 32 && r < 127) || r == '\n' || r == '\t' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (de *DetectionEngine) GetRules() []Rule {
	return de.rules
}

func GetHighestSeverity(detections []Detection) Severity {
	order := map[Severity]int{
		SeverityCritical: 4,
		SeverityHigh:     3,
		SeverityMedium:   2,
		SeverityLow:      1,
	}
	best := SeverityLow
	bestVal := 0
	for _, d := range detections {
		if v, ok := order[d.Severity]; ok && v > bestVal {
			best = d.Severity
			bestVal = v
		}
	}
	return best
}
