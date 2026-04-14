package ebpf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ProcessInfo struct {
	PID  uint32
	Name string
	Cmdline string
}

func findTargetProcesses(targetNames []string) ([]ProcessInfo, error) {
	var processes []ProcessInfo

	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		commPath := filepath.Join(procDir, entry.Name(), "comm")
		commData, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		commName := strings.TrimSpace(string(commData))

		// Check if this process matches our targets
		for _, target := range targetNames {
			if strings.Contains(commName, target) {
				cmdline := readProcCmdline(uint32(pid))
				processes = append(processes, ProcessInfo{
					PID:     uint32(pid),
					Name:    commName,
					Cmdline: cmdline,
				})
				break
			}
		}
	}

	return processes, nil
}

func readProcCmdline(pid uint32) string {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(string(data), "\x00", " ")
}

func ListRunningProcesses() ([]ProcessInfo, error) {
	var processes []ProcessInfo

	procDir := "/proc"
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		commPath := filepath.Join(procDir, entry.Name(), "comm")
		commData, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}

		commName := strings.TrimSpace(string(commData))
		cmdline := readProcCmdline(uint32(pid))

		processes = append(processes, ProcessInfo{
			PID:     uint32(pid),
			Name:    commName,
			Cmdline: cmdline,
		})
	}

	return processes, nil
}

func ReadProcMaps(pid uint32) ([]string, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, scanner.Err()
}
