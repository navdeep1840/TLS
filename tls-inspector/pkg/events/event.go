package events

import (
	"encoding/json"
	"time"
)

type TLSEvent struct {
	Timestamp       time.Time  `json:"timestamp"`
	Process         string     `json:"process"`
	PID             uint32     `json:"pid"`
	TID             uint32     `json:"tid"`
	UID             uint32     `json:"uid"`
	CommandLine     string     `json:"cmdline,omitempty"`
	ContainerID     string     `json:"container_id,omitempty"`
	PodName         string     `json:"pod_name,omitempty"`
	Namespace       string     `json:"namespace,omitempty"`
	Library         string     `json:"library"`
	Function        string     `json:"function"`
	Direction       string     `json:"direction"`
	DataLen         uint32     `json:"data_len"`
	PlaintextPreview string    `json:"plaintext_preview"`
	Detections      []string   `json:"detections,omitempty"`
	Severity        string     `json:"severity,omitempty"`
}

type RawTLSEvent struct {
	Timestamp    uint64
	PID          uint32
	TID          uint32
	UID          uint32
	CgroupID     uint64
	Comm         [16]byte
	FunctionType uint8
	DataLen      uint32
	Data         [4096]byte
}

func (e *TLSEvent) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

func GetFunctionName(funcType uint8) string {
	switch funcType {
	case 0:
		return "SSL_write"
	case 1:
		return "SSL_read"
	case 2:
		return "SSL_write_ex"
	case 3:
		return "SSL_read_ex"
	default:
		return "unknown"
	}
}

func GetDirection(funcType uint8) string {
	if funcType == 0 || funcType == 2 {
		return "egress"
	}
	return "ingress"
}
