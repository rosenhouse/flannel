package fdb

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/coreos/flannel/pkg/ip"
)

type UDPForwardingDB interface {
	Add(overlaySubnet ip.IP4Net, underlayEndpoint *net.UDPAddr) error
	Remove(overlaySubnet ip.IP4Net) error
	FindUnderlayEndpoint(overlayIP ip.IP4) (*net.UDPAddr, error)
}

var ErrorMissingEntry = errors.New("missing fdb entry")

func NewUDPForwardingDB() UDPForwardingDB {
	return &forwardingDB{}
}

type entry struct {
	overlaySubnet    ip.IP4Net
	underlayEndpoint *net.UDPAddr
}

func (e entry) String() string {
	return fmt.Sprintf("%s -> %s", e.overlaySubnet.String(), e.underlayEndpoint.String())
}

type forwardingDB struct {
	entries []entry
	lock    sync.Mutex
}

func (d *forwardingDB) Add(overlaySubnet ip.IP4Net, underlayEndpoint *net.UDPAddr) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.entries = append(d.entries, entry{
		overlaySubnet:    overlaySubnet,
		underlayEndpoint: underlayEndpoint,
	})
	return nil
}

func (d *forwardingDB) Remove(overlaySubnet ip.IP4Net) error {
	d.lock.Lock()
	defer d.lock.Unlock()

	toRemove := -1
	for i, en := range d.entries {
		if en.overlaySubnet.Equal(overlaySubnet) {
			toRemove = i
		}
	}
	if toRemove < 0 {
		return fmt.Errorf("subnet does not exist in fdb: %s", overlaySubnet)
	}
	d.swap(toRemove, len(d.entries)-1)
	d.entries = d.entries[:len(d.entries)-1]
	return nil
}

func (d *forwardingDB) swap(i, j int) {
	temp := d.entries[i]
	d.entries[i] = d.entries[j]
	d.entries[j] = temp
}

func (d *forwardingDB) FindUnderlayEndpoint(overlayIP ip.IP4) (*net.UDPAddr, error) {
	for _, en := range d.entries {
		if en.overlaySubnet.Contains(overlayIP) {
			return en.underlayEndpoint, nil
		}
	}
	return nil, ErrorMissingEntry
}
