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
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"policy-server/client"
	"time"

	log "github.com/coreos/flannel/Godeps/_workspace/src/github.com/golang/glog"
	"github.com/coreos/flannel/Godeps/_workspace/src/golang.org/x/net/context"
	"github.com/pivotal-golang/lager"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/fdb"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/pkg/policy"
	"github.com/coreos/flannel/subnet"
)

func init() {
	backend.Register("udpgo", New)
}

const (
	defaultPort = 8285
)

type UdpgoBackend struct {
	subnetManager subnet.Manager
	extIface      *backend.ExternalInterface
}

func New(subnetManager subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	be := UdpgoBackend{
		subnetManager: subnetManager,
		extIface:      extIface,
	}
	return &be, nil
}

func (be *UdpgoBackend) RegisterNetwork(ctx context.Context, netname string, config *subnet.Config) (backend.Network, error) {
	cfg := struct {
		Port            int
		PolicyURL       string
		LocalListenAddr string
	}{
		Port:            defaultPort,
		PolicyURL:       "",
		LocalListenAddr: "127.0.0.1:9022",
	}

	// Parse our configuration
	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding UDP backend config: %v", err)
		}
	}

	log.Infof("udpgo backend: parsed config %#v", cfg)

	// Acquire the lease form subnet manager
	attrs := subnet.LeaseAttrs{
		PublicIP: ip.FromIP(be.extIface.ExtAddr),
	}

	lease, err := be.subnetManager.AcquireLease(ctx, netname, &attrs)
	switch err {
	case nil:

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	// Tunnel's subnet is that of the whole overlay network (e.g. /16)
	// and not that of the individual host (e.g. /24)
	tunNet := ip.IP4Net{
		IP:        lease.Subnet.IP,
		PrefixLen: config.Network.PrefixLen,
	}

	forwardingDB := fdb.NewUDPForwardingDB()
	const tagLength = 4

	logger := lager.NewLogger("udpgo")
	logger.RegisterSink(lager.NewWriterSink(os.Stdout, lager.INFO))

	controlTag := []byte("ctrl")
	localPolicy := policy.NewDynamicPolicy(logger.Session("policy"), tagLength, tunNet.IP.ToIP(), controlTag)

	policyHandler := &policy.Handler{
		Logger:          logger.Session("policy-handler"),
		LocalListenAddr: cfg.LocalListenAddr,
		Registrar:       localPolicy,
	}

	var timeoutClient = &http.Client{
		Timeout: time.Second * 10,
	}

	policyPoller := &policy.Poller{
		Logger:             logger.Session("policy-poller"),
		PollInterval:       5 * time.Second,
		LocalDB:            localPolicy,
		PolicyServerClient: client.NewInnerClient(cfg.PolicyURL, timeoutClient),
	}
	go func() {
		err := policyHandler.RunServer()
		if err != nil {
			logger.Fatal("policy-controller-server", err)
		}
	}()
	go func() {
		err := policyPoller.RunPoller()
		if err != nil {
			logger.Fatal("policy-controller-poller", err)
		}
	}()

	return newNetwork(netname, be.subnetManager, be.extIface, cfg.Port, tunNet,
		lease, forwardingDB, localPolicy)
}

func (_ *UdpgoBackend) Run(ctx context.Context) {
	<-ctx.Done()
}
