// Package output renders TLS inspection events as human-readable alerts.
package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/emergent/tls-inspector/pkg/detector"
	"github.com/emergent/tls-inspector/pkg/events"
)

// ANSI color codes
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	white  = "\033[37m"
	gray   = "\033[90m"
	green  = "\033[32m"
)

const lineWidth = 72

func severityColor(s detector.Severity) string {
	switch s {
	case detector.SeverityCritical:
		return bold + red
	case detector.SeverityHigh:
		return bold + yellow
	case detector.SeverityMedium:
		return cyan
	default:
		return white
	}
}

func severityLabel(s detector.Severity) string {
	switch s {
	case detector.SeverityCritical:
		return "CRITICAL"
	case detector.SeverityHigh:
		return "HIGH    "
	case detector.SeverityMedium:
		return "MEDIUM  "
	default:
		return "LOW     "
	}
}

func divider(char string) string {
	return strings.Repeat(char, lineWidth)
}

// PrintAlert renders a detection alert to stdout in structured human-readable form.
func PrintAlert(ev *events.TLSEvent, detections []detector.Detection) {
	if len(detections) == 0 {
		return
	}

	highest := detector.GetHighestSeverity(detections)
	sColor := severityColor(highest)
	sLabel := severityLabel(highest)

	ts := ev.Timestamp.Format(time.RFC3339)
	direction := strings.ToUpper(ev.Direction)

	fmt.Println()
	fmt.Printf("%s%s%s\n", sColor, divider("━"), reset)

	// Header line
	header := fmt.Sprintf("  %s[%s]%s  %d rule(s) matched   %s%s%s",
		sColor+bold, sLabel, reset,
		len(detections),
		gray, ts, reset,
	)
	fmt.Println(header)

	fmt.Printf("%s%s%s\n", gray, divider("─"), reset)

	// Process info
	fmt.Printf("  %sProcess%s   %s  (pid=%-6d uid=%d)\n",
		bold, reset, ev.Process, ev.PID, ev.UID)

	if ev.CommandLine != "" {
		cmd := ev.CommandLine
		if len(cmd) > 80 {
			cmd = cmd[:77] + "..."
		}
		fmt.Printf("  %sCmdline%s   %s\n", bold, reset, cmd)
	}

	if ev.ContainerID != "" {
		fmt.Printf("  %sContainer%s %s", bold, reset, ev.ContainerID)
		if ev.PodName != "" {
			fmt.Printf("  pod=%s", ev.PodName)
		}
		if ev.Namespace != "" {
			fmt.Printf("  ns=%s", ev.Namespace)
		}
		fmt.Println()
	}

	fmt.Printf("  %sFlow%s      %s%s%s  via %s  (%d bytes)\n",
		bold, reset,
		directionTag(direction), direction, reset,
		ev.Function,
		ev.DataLen,
	)

	// Detections
	fmt.Printf("%s%s%s\n", gray, divider("─"), reset)
	fmt.Printf("  %sDetections:%s\n", bold, reset)

	for i, det := range detections {
		dc := severityColor(det.Severity)
		fmt.Printf("\n  %s[%d] %s%s  %s(%s)%s\n",
			dc+bold, i+1, det.RuleName, reset,
			gray, det.Severity, reset,
		)

		for _, m := range det.Matches {
			// Truncate long matched values
			val := m.Value
			if len(val) > 60 {
				val = val[:57] + "..."
			}
			val = strings.ReplaceAll(val, "\n", " ")
			val = strings.ReplaceAll(val, "\r", "")

			ctx := m.Context
			ctx = strings.ReplaceAll(ctx, "\n", " ")
			ctx = strings.ReplaceAll(ctx, "\r", "")

			fmt.Printf("      %sType%s     %s\n", gray, reset, m.Type)
			fmt.Printf("      %sMatched%s  %s%s%s\n", gray, reset, bold, val, reset)
			if ctx != "" && ctx != val {
				fmt.Printf("      %sContext%s  %s\n", gray, reset, ctx)
			}
		}
	}

	fmt.Printf("%s%s%s\n", sColor, divider("━"), reset)
}

// PrintTraffic renders a non-detection traffic event (used with --all-traffic).
func PrintTraffic(ev *events.TLSEvent) {
	ts := ev.Timestamp.Format("15:04:05.000")
	direction := strings.ToUpper(ev.Direction)
	preview := ev.PlaintextPreview
	if len(preview) > 120 {
		preview = preview[:117] + "..."
	}
	preview = strings.ReplaceAll(preview, "\n", " ")
	preview = strings.ReplaceAll(preview, "\r", "")

	fmt.Printf("%s%s%s  %s%-8s%s  %s  %s(pid=%d)%s  %s%s%s\n",
		gray, ts, reset,
		directionTag(direction), direction, reset,
		ev.Function,
		gray, ev.PID, reset,
		gray, preview, reset,
	)
}

func directionTag(direction string) string {
	if direction == "EGRESS" {
		return red + "↑ "
	}
	return green + "↓ "
}
