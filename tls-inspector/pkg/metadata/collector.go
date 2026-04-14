package metadata

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ProcessMetadata struct {
	Cmdline     string
	ContainerID string
	PodName     string
	Namespace   string
}

func GetProcessMetadata(pid uint32) (*ProcessMetadata, error) {
	meta := &ProcessMetadata{}
	
	// Get command line
	cmdline, err := readCmdline(pid)
	if err == nil {
		meta.Cmdline = cmdline
	}
	
	// Get container info from cgroup
	containerID, err := getContainerID(pid)
	if err == nil {
		meta.ContainerID = containerID
		
		// Try to get K8s metadata
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
	
	// Replace null bytes with spaces
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(cmdline), nil
}

func getContainerID(pid uint32) (string, error) {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		
		// Docker/containerd pattern: .../docker/<container_id>
		if strings.Contains(line, "/docker/") {
			parts := strings.Split(line, "/docker/")
			if len(parts) > 1 {
				containerID := strings.TrimSuffix(parts[1], ".scope")
				if len(containerID) >= 12 {
					return containerID[:12], nil
				}
			}
		}
		
		// containerd pattern: .../cri-containerd-<container_id>
		if strings.Contains(line, "cri-containerd-") {
			parts := strings.Split(line, "cri-containerd-")
			if len(parts) > 1 {
				containerID := strings.TrimSuffix(parts[1], ".scope")
				if len(containerID) >= 12 {
					return containerID[:12], nil
				}
			}
		}
		
		// K8s pod pattern: .../pod<pod_id>/
		if strings.Contains(line, "/pod") {
			parts := strings.Split(line, "/")
			for _, part := range parts {
				if strings.HasPrefix(part, "crio-") || strings.HasPrefix(part, "docker-") {
					containerID := strings.TrimPrefix(part, "crio-")
					containerID = strings.TrimPrefix(containerID, "docker-")
					containerID = strings.TrimSuffix(containerID, ".scope")
					if len(containerID) >= 12 {
						return containerID[:12], nil
					}
				}
			}
		}
	}
	
	return "", fmt.Errorf("no container ID found")
}

func getK8sMetadata(pid uint32) (string, string) {
	// Best effort K8s metadata extraction
	// Look for environment variables in /proc/<pid>/environ
	path := fmt.Sprintf("/proc/%d/environ", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	
	envVars := strings.Split(string(data), "\x00")
	var podName, namespace string
	
	for _, env := range envVars {
		if strings.HasPrefix(env, "KUBERNETES_POD_NAME=") {
			podName = strings.TrimPrefix(env, "KUBERNETES_POD_NAME=")
		} else if strings.HasPrefix(env, "POD_NAME=") {
			podName = strings.TrimPrefix(env, "POD_NAME=")
		} else if strings.HasPrefix(env, "KUBERNETES_NAMESPACE=") {
			namespace = strings.TrimPrefix(env, "KUBERNETES_NAMESPACE=")
		} else if strings.HasPrefix(env, "POD_NAMESPACE=") {
			namespace = strings.TrimPrefix(env, "POD_NAMESPACE=")
		}
	}
	
	return podName, namespace
}

func FindLibraryPath(pid uint32, libName string) (string, error) {
	path := fmt.Sprintf("/proc/%d/maps", pid)
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, libName) && strings.HasSuffix(line, ".so") ||
			strings.Contains(line, libName+".") {
			parts := strings.Fields(line)
			if len(parts) >= 6 {
				return parts[5], nil
			}
		}
	}
	
	// Try standard library paths
	standardPaths := []string{
		"/usr/lib/x86_64-linux-gnu/" + libName,
		"/usr/lib64/" + libName,
		"/usr/lib/" + libName,
		"/lib/x86_64-linux-gnu/" + libName,
	}
	
	for _, p := range standardPaths {
		matches, _ := filepath.Glob(p + "*")
		if len(matches) > 0 {
			return matches[0], nil
		}
	}
	
	return "", fmt.Errorf("library %s not found for pid %d", libName, pid)
}
