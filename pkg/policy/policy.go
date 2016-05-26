package policy

import (
	"net"
	"policy-server/models"
)

type LocalPolicy interface {
	TagLength() int
	GetSourceTag(localSource net.IP) ([]byte, error)
	IsAllowed(remoteSourceTag []byte, localDest net.IP) (bool, error)
}

type LocalDB interface {
	GetGroups() ([]string, error)
	SetWhitelists([]models.IngressWhitelist) error
}

type Endpoint struct {
	ContainerID string
	GroupID     string
	OverlayIP   net.IP
}

type EndpointCollection interface {
	Register(Endpoint) error
	Deregister(Endpoint) error
}

type DynamicPolicy interface {
	LocalPolicy
	LocalDB
	EndpointCollection
}
