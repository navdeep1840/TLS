package metadata

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type ProcessMetadata struct {
	Cmdline     string
	ContainerID string
	PodName     string
	Namespace   string
}

// containerIDRe matches a 64-hex-char container ID or the 12-char short form.
var containerIDRe = regexp.MustCompile(`[a-f0-9]{64}|[a-f0-9]{12}`)

func GetProcessMetadata(pid uint32) (*ProcessMetadata, error) {
	meta := &ProcessMetadata{}

	if cmdline, err := readCmdline(pid); err == nil {
		meta.Cmdline = cmdline
	}

	if id := extractContainerID(pid); id != "" {
		meta.ContainerID = id
		podName, namespace := getK8sMetadata(pid)
		meta.PodName = podName
		meta.Namespace = namespace
	}

	return meta, nil
}

func readCmdline(pid uint32) (string, error) {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " ")), nil
}

// extractContainerID parses /proc/<pid>/cgroup for a container ID.
// Handles Docker, containerd, cri-o, and cgroupv2 unified hierarchy.
func extractContainerID(pid uint32) string {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Patterns found in cgroup entries:
		//   .../docker/<64hex>
		//   .../docker/<64hex>.scope
		//   .../cri-containerd-<64hex>.scope
		//   .../crio-<64hex>.scope
		//   .../containerd/<namespace>/<64hex>
		//   cgroupv2: 0::/<path> where path contains the 64-hex ID

		// Fast path: look for known prefixes
		for _, prefix := range []string{"/docker/", "cri-containerd-", "crio-", "/containerd/"} {
			if idx := strings.Index(line, prefix); idx >= 0 {
				fragment := line[idx+len(prefix):]
				fragment = strings.TrimSuffix(fragment, ".scope")
				// The container ID may be followed by more path components
				fragment = strings.SplitN(fragment, "/", 2)[0]
				if m := containerIDRe.FindString(fragment); m != "" {
					if len(m) == 64 {
						return m[:12]
					}
					return m
				}
			}
		}

		// Generic: find any 64-hex run in the line
		if m := regexp.MustCompile(`[a-f0-9]{64}`).FindString(line); m != "" {
			return m[:12]
		}
	}
	return ""
}

func getK8sMetadata(pid uint32) (podName, namespace string) {
	path := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}

	for _, env := range strings.Split(string(data), "\x00") {
		switch {
		case strings.HasPrefix(env, "KUBERNETES_POD_NAME="):
			podName = strings.TrimPrefix(env, "KUBERNETES_POD_NAME=")
		case strings.HasPrefix(env, "POD_NAME="):
			podName = strings.TrimPrefix(env, "POD_NAME=")
		case strings.HasPrefix(env, "HOSTNAME=") && podName == "":
			// K8s sets HOSTNAME to the pod name
			podName = strings.TrimPrefix(env, "HOSTNAME=")
		case strings.HasPrefix(env, "KUBERNETES_NAMESPACE="):
			namespace = strings.TrimPrefix(env, "KUBERNETES_NAMESPACE=")
		case strings.HasPrefix(env, "POD_NAMESPACE="):
			namespace = strings.TrimPrefix(env, "POD_NAMESPACE=")
		}
	}
	return
}

// FindLibraryPath searches /proc/<pid>/maps for a library matching libName,
// then falls back to well-known filesystem paths.
func FindLibraryPath(pid uint32, libName string) (string, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, libName) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		p := fields[5]
		if strings.HasSuffix(p, ".so") || strings.Contains(p, ".so.") {
			return p, nil
		}
	}

	// Fallback: glob standard locations
	for _, pattern := range []string{
		"/usr/lib/x86_64-linux-gnu/" + libName + "*.so*",
		"/usr/lib64/" + libName + "*.so*",
		"/usr/lib/" + libName + "*.so*",
		"/lib/x86_64-linux-gnu/" + libName + "*.so*",
	} {
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			return matches[0], nil
		}
	}

	return "", fmt.Errorf("library %s not found for pid %d", libName, pid)
}
