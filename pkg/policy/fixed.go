package policy

import (
	"bytes"
	"fmt"
	"net"
)

type fixed struct {
	tag []byte
}

func NewFixedPolicy(tag []byte) LocalPolicy {
	return &fixed{
		tag: tag,
	}
}

func (p *fixed) TagLength() int {
	return len(p.tag)
}

func (p *fixed) GetSourceTag(localSource net.IP) ([]byte, error) {
	return p.tag, nil
}

func (p *fixed) IsAllowed(remoteSourceTag []byte, localDest net.IP) (bool, error) {
	if len(remoteSourceTag) != len(p.tag) {
		return false, fmt.Errorf("bad tag length: got %d, expected %d", len(remoteSourceTag), len(p.tag))
	}
	return bytes.Equal(remoteSourceTag, p.tag), nil
}
