// Package netinfo extracts remote IP addresses from a process's active
// TCP connections by correlating /proc/<pid>/fd socket inodes with
// /proc/<pid>/net/tcp entries — so only IPs for *this process's* sockets
// are returned, not every connection in the network namespace.
package netinfo

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
)

const tcpEstablished = "01"

// GetRemoteIPs returns the unique public remote IPs for ESTABLISHED TCP
// connections that belong specifically to the given pid's open file descriptors.
func GetRemoteIPs(pid uint32) []string {
	// Step 1: collect socket inodes from the process's open fds
	inodes := processSocketInodes(pid)
	if len(inodes) == 0 {
		return nil
	}

	// Step 2: match those inodes against /proc/<pid>/net/tcp[6]
	seen := make(map[string]struct{})
	var ips []string

	for _, ip := range matchTCPTable(pid, inodes, false) {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			ips = append(ips, ip)
		}
	}
	for _, ip := range matchTCPTable(pid, inodes, true) {
		if _, ok := seen[ip]; !ok {
			seen[ip] = struct{}{}
			ips = append(ips, ip)
		}
	}
	return ips
}

// processSocketInodes reads /proc/<pid>/fd/ and returns the set of socket
// inodes (from symlinks like "socket:[1234567]") for this process.
func processSocketInodes(pid uint32) map[string]struct{} {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}

	inodes := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		target, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, e.Name()))
		if err != nil {
			continue
		}
		// socket fds look like: socket:[1234567]
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inode := target[len("socket:[") : len(target)-1]
			inodes[inode] = struct{}{}
		}
	}
	return inodes
}

// matchTCPTable parses /proc/<pid>/net/tcp (or tcp6) and returns remote IPs
// of ESTABLISHED rows whose inode is in the provided set.
//
// /proc/net/tcp columns (space-separated):
//
//	sl  local_address  rem_address  st  tx_queue:rx_queue  tr:tm->when  retrnsmt  uid  timeout  inode
//	 0       1              2        3          4                5           6       7     8        9
func matchTCPTable(pid uint32, inodes map[string]struct{}, ipv6 bool) []string {
	file := fmt.Sprintf("/proc/%d/net/tcp", pid)
	if ipv6 {
		file += "6"
	}

	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()

	var ips []string
	sc := bufio.NewScanner(f)
	sc.Scan() // skip header

	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		// state must be ESTABLISHED
		if fields[3] != tcpEstablished {
			continue
		}
		// inode is field[9] — must belong to this process
		if _, owned := inodes[fields[9]]; !owned {
			continue
		}
		// rem_address is field[2]: HEXIP:HEXPORT
		parts := strings.SplitN(fields[2], ":", 2)
		if len(parts) != 2 {
			continue
		}
		ip := hexToIP(parts[0], ipv6)
		if ip == nil || isPrivate(ip) {
			continue
		}
		ips = append(ips, ip.String())
	}
	return ips
}

// hexToIP decodes the kernel's hex-encoded IP address.
// IPv4: 8 hex chars, little-endian 32-bit word.
// IPv6: 32 hex chars, four 32-bit little-endian words.
func hexToIP(h string, ipv6 bool) net.IP {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil
	}
	if !ipv6 {
		if len(b) != 4 {
			return nil
		}
		binary.BigEndian.PutUint32(b, binary.LittleEndian.Uint32(b))
		return net.IP(b)
	}
	if len(b) != 16 {
		return nil
	}
	out := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		word := binary.LittleEndian.Uint32(b[i*4 : i*4+4])
		binary.BigEndian.PutUint32(out[i*4:], word)
	}
	return out
}

var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"169.254.0.0/16",
		"0.0.0.0/8",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, block)
	}
}

func isPrivate(ip net.IP) bool {
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}
