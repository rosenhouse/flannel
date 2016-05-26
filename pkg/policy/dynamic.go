package policy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"policy-server/models"
	"sync"

	"github.com/coreos/flannel/pkg/ip"
	"github.com/pivotal-golang/lager"
)

type WhitelistIndex map[ip.IP4]models.IngressWhitelist

func (i WhitelistIndex) MarshalJSON() ([]byte, error) {
	toMarshal := make(map[string]models.IngressWhitelist)
	for k, v := range i {
		toMarshal[k.String()] = v
	}
	return json.Marshal(toMarshal)
}

type dynamic struct {
	logger lager.Logger

	tagLength int
	lock      sync.Mutex

	endpoints []Endpoint
	index     WhitelistIndex

	tunnelEndpointIP net.IP
	controlTag       []byte
}

func NewDynamicPolicy(logger lager.Logger, tagLength int, tunnelEndpointIP net.IP, controlTag []byte) DynamicPolicy {
	return &dynamic{
		logger:           logger,
		tagLength:        tagLength,
		lock:             sync.Mutex{},
		index:            make(map[ip.IP4]models.IngressWhitelist),
		tunnelEndpointIP: tunnelEndpointIP,
		controlTag:       controlTag,
	}
}

func (p *dynamic) SetWhitelists(whitelists []models.IngressWhitelist) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	newIndex := make(WhitelistIndex)
	for _, wl := range whitelists {
		destGroup := wl.Destination.ID
		for _, ep := range p.endpoints {
			if ep.GroupID != destGroup {
				continue
			}

			newIndex[ip.FromIP(ep.OverlayIP)] = wl
		}
	}

	p.logger.Info("new-index", lager.Data{"index": newIndex})

	p.index = newIndex
	return nil
}

func (p *dynamic) TagLength() int {
	return p.tagLength
}

var ErrorUnknownLocalSource = errors.New("unknown local source")

func (p *dynamic) GetSourceTag(localSource net.IP) ([]byte, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	if localSource.Equal(p.tunnelEndpointIP) {
		return p.controlTag, nil
	}

	indexElement, ok := p.index[ip.FromIP(localSource)]
	if !ok {
		p.logger.Info("unknown-local-source", lager.Data{"source": localSource})
		return nil, ErrorUnknownLocalSource
	} else {
		p.logger.Info("tagging", lager.Data{"source": indexElement})
		return *indexElement.Destination.Tag, nil
	}
}

func (p *dynamic) IsAllowed(remoteSourceTag []byte, localDest net.IP) (bool, error) {
	if len(remoteSourceTag) != p.tagLength {
		return false, fmt.Errorf("bad tag length: got %d, expected %d", len(remoteSourceTag), p.tagLength)
	}

	if bytes.Equal(remoteSourceTag, p.controlTag) {
		p.logger.Info("allowed-control-tag")
		return true, nil
	}

	if localDest.Equal(p.tunnelEndpointIP) {
		p.logger.Info("allowed-dest-endpoint")
		return true, nil
	}

	whitelist, ok := p.index[ip.FromIP(localDest)]
	if !ok {
		p.logger.Info("unknown-destination", lager.Data{"src-tag": hex.EncodeToString(remoteSourceTag), "dst-ip": localDest})
		return false, nil
	}

	for _, allowedSource := range whitelist.AllowedSources {
		if bytes.Equal(remoteSourceTag, *allowedSource.Tag) {
			p.logger.Info("allowed", lager.Data{"remote-source": allowedSource, "local-dest": whitelist.Destination})
			return true, nil
		}
	}

	p.logger.Info("denied", lager.Data{"remote-source-tag": hex.EncodeToString(remoteSourceTag), "local-dest": whitelist.Destination})
	return false, nil
}

func (p *dynamic) Register(endpoint Endpoint) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.endpoints = append(p.endpoints, endpoint)
	return nil
}

func (p *dynamic) Deregister(endpoint Endpoint) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	reduced := []Endpoint{}
	for _, ep := range p.endpoints {
		if ep.ContainerID != endpoint.ContainerID {
			reduced = append(reduced, ep)
		}
	}
	if len(reduced) == len(p.endpoints) {
		return fmt.Errorf("no endpoint found to remove, missing container id %s", endpoint.ContainerID)
	}

	p.endpoints = reduced
	return nil
}

func (p *dynamic) GetGroups() ([]string, error) {
	p.lock.Lock()
	defer p.lock.Unlock()

	groups := []string{}
	for _, ep := range p.endpoints {
		groups = append(groups, ep.GroupID)
	}
	return groups, nil
}
