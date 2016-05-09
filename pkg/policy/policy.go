package policy

import (
	"bytes"
	"fmt"
	"net"
)

type LocalPolicy interface {
	TagLength() int
	GetSourceTag(localSource net.IP) ([]byte, error)
	IsAllowed(remoteSourceTag []byte, localDest net.IP) (bool, error)
}

type fixedPolicy struct {
	tag []byte
}

func NewFixedPolicy(tag []byte) LocalPolicy {
	return &fixedPolicy{
		tag: tag,
	}
}

func (p *fixedPolicy) TagLength() int {
	return len(p.tag)
}

func (p *fixedPolicy) GetSourceTag(localSource net.IP) ([]byte, error) {
	return p.tag, nil
}

func (p *fixedPolicy) IsAllowed(remoteSourceTag []byte, localDest net.IP) (bool, error) {
	if len(remoteSourceTag) != len(p.tag) {
		return false, fmt.Errorf("bad tag length: got %d, expected %d", len(remoteSourceTag), len(p.tag))
	}
	return bytes.Equal(remoteSourceTag, p.tag), nil
}
