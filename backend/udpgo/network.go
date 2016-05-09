// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package udpgo

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	log "github.com/coreos/flannel/Godeps/_workspace/src/github.com/golang/glog"
	"github.com/coreos/flannel/Godeps/_workspace/src/github.com/vishvananda/netlink"
	"github.com/coreos/flannel/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/fdb"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
)

const (
	encapOverhead = 28 // 20 bytes IP hdr + 8 bytes UDP hdr
)

type network struct {
	backend.SimpleNetwork
	name          string
	port          int
	tunIO         *water.Interface
	udpConn       *net.UDPConn
	tunNet        ip.IP4Net
	subnetManager subnet.Manager
	forwardingDB  fdb.UDPForwardingDB
}

func newNetwork(
	name string, subnetManager subnet.Manager, extIface *backend.ExternalInterface,
	port int, tunNetwork ip.IP4Net, l *subnet.Lease) (*network, error) {

	n := &network{
		SimpleNetwork: backend.SimpleNetwork{
			SubnetLease: l,
			ExtIface:    extIface,
		},
		name:          name,
		port:          port,
		subnetManager: subnetManager,
		tunNet:        tunNetwork,
		forwardingDB:  fdb.NewUDPForwardingDB(),
	}

	if err := n.initTun(); err != nil {
		return nil, err
	}

	var err error
	n.udpConn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: extIface.IfaceAddr, Port: port})
	if err != nil {
		return nil, fmt.Errorf("failed to start listening on UDP socket: %v", err)
	}

	log.Info("created new udpgo network")

	return n, nil
}

func (n *network) Run(ctx context.Context) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	defer func() {
		n.tunIO.Close()
		n.udpConn.Close()
	}()

	wg.Add(1)
	go func() {
		log.Info("starting tun --> udp")
		n.tunToUDP(ctx)
		wg.Done()
		log.Info("done with tun --> udp")
	}()

	wg.Add(1)
	go func() {
		log.Info("starting udp --> tun")
		n.udpToTun(ctx)
		wg.Done()
		log.Info("done udp --> tun")
	}()

	log.Info("Watching for new subnet leases")
	evts := make(chan []subnet.Event)
	wg.Add(1)
	go func() {
		log.Info("watching for leases")
		subnet.WatchLeases(ctx, n.subnetManager, n.name, n.SubnetLease, evts)
		wg.Done()
		log.Info("done watching for leases")
	}()

	for {
		select {
		case evtBatch := <-evts:
			n.processSubnetEvents(evtBatch)

		case <-ctx.Done():
			log.Info("received done signal, shutting down")
			return
		}
	}
}

func (n *network) tunToUDP(ctx context.Context) {
	tunBuffer := make([]byte, n.MTU())
	for {
		select {
		case <-ctx.Done():
			return
		default:
			nBytesRead, err := n.tunIO.Read(tunBuffer)
			if err != nil {
				log.Errorf("tun read: %s", err)
				continue
			}
			if nBytesRead < 1 {
				log.Info("tun empty read")
				continue
			}
			toSend := tunBuffer[:nBytesRead]
			dest, err := n.findDest(toSend)
			if err != nil {
				log.Errorf("find dest: %s", err)
				continue
			}
			if _, err := n.udpConn.WriteToUDP(toSend, dest); err != nil {
				log.Errorf("send udp: %s", err)
				continue
			}
		}
	}
}

func (n *network) udpToTun(ctx context.Context) {
	udpPayload := make([]byte, n.MTU())
	for {
		select {
		case <-ctx.Done():
			return
		default:
			nBytesRead, _, err := n.udpConn.ReadFromUDP(udpPayload)
			if err != nil {
				log.Errorf("udp read: %s", err)
				continue
			}
			if nBytesRead < 1 {
				log.Info("udp empty read")
				continue
			}
			// TODO: apply ingress policy here
			if _, err := n.tunIO.Write(udpPayload); err != nil {
				log.Errorf("write to tun: %s", err)
				continue
			}
		}
	}
}

func (n *network) MTU() int {
	return n.ExtIface.Iface.MTU - encapOverhead
}

func (n *network) initTun() error {
	var err error

	n.tunIO, err = water.NewTUN("flannel%d")
	if err != nil {
		return fmt.Errorf("failed to open TUN device: %v", err)
	}

	tunName := n.tunIO.Name()

	err = configureIface(tunName, n.tunNet, n.MTU())
	if err != nil {
		return err
	}

	return nil
}

func configureIface(ifname string, ipn ip.IP4Net, mtu int) error {
	iface, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("failed to lookup interface %v", ifname)
	}

	err = netlink.AddrAdd(iface, &netlink.Addr{ipn.ToIPNet(), ""})
	if err != nil {
		return fmt.Errorf("failed to add IP address %v to %v: %v", ipn.String(), ifname, err)
	}

	err = netlink.LinkSetMTU(iface, mtu)
	if err != nil {
		return fmt.Errorf("failed to set MTU for %v: %v", ifname, err)
	}

	err = netlink.LinkSetUp(iface)
	if err != nil {
		return fmt.Errorf("failed to set interface %v to UP state: %v", ifname, err)
	}

	// explicitly add a route since there might be a route for a subnet already
	// installed by Docker and then it won't get auto added
	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: iface.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       ipn.Network().ToIPNet(),
	})
	if err != nil && err != syscall.EEXIST {
		return fmt.Errorf("failed to add route (%v -> %v): %v", ipn.Network().String(), ifname, err)
	}

	return nil
}

func (n *network) processSubnetEvents(batch []subnet.Event) {
	for _, evt := range batch {
		switch evt.Type {
		case subnet.EventAdded:
			log.Info("Subnet added: ", evt.Lease.Subnet)

			n.setRoute(evt.Lease.Subnet, evt.Lease.Attrs.PublicIP)

		case subnet.EventRemoved:
			log.Info("Subnet removed: ", evt.Lease.Subnet)

			n.removeRoute(evt.Lease.Subnet)

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}

func (n *network) setRoute(subnet ip.IP4Net, destIP ip.IP4) {
	log.Infof("set %s --> %s:%d", subnet, destIP, n.port)
	err := n.forwardingDB.Add(subnet, &net.UDPAddr{
		IP:   destIP.ToIP(),
		Port: n.port,
	})
	if err != nil {
		log.Errorf("add route: %s", err)
	}
}

func (n *network) removeRoute(subnet ip.IP4Net) {
	log.Infof("remove %s", subnet)
	if err := n.forwardingDB.Remove(subnet); err != nil {
		log.Errorf("remove route: %s", err)
	}
}

func (n *network) findDest(tunPacket []byte) (*net.UDPAddr, error) {
	overlayIP := waterutil.IPv4Destination(tunPacket)
	return n.forwardingDB.FindUnderlayEndpoint(ip.FromIP(overlayIP))
}
