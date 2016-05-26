package policy

import (
	"fmt"
	"policy-server/models"
	"time"

	"github.com/pivotal-golang/lager"
)

type innerClient interface {
	GetWhitelists(groupIDs []string) ([]models.IngressWhitelist, error)
}

type Poller struct {
	Logger             lager.Logger
	PollInterval       time.Duration
	PolicyServerClient innerClient
	LocalDB            LocalDB
}

func (c *Poller) RunPoller() error {
	logger := c.Logger.Session("poller")
	logger.Info("start", lager.Data{
		"interval": c.PollInterval,
	})
	for {
		err := c.SyncOnce()
		if err != nil {
			logger.Error("poll", err)
		}
		time.Sleep(c.PollInterval)
	}

	return nil
}

func (c *Poller) SyncOnce() error {
	logger := c.Logger.Session("sync-once")
	logger.Info("start")
	defer logger.Info("done")

	groups, err := c.LocalDB.GetGroups()
	if err != nil {
		return fmt.Errorf("get groups: %s", err)
	}
	if groups == nil {
		logger.Info("no-groups")
		return nil
	}
	logger.Info("got-groups", lager.Data{"groups": groups})

	whitelists, err := c.PolicyServerClient.GetWhitelists(groups)
	if err != nil {
		return fmt.Errorf("get whitelists: %s", err)
	}
	logger.Info("got-whitelists", lager.Data{"whitelists": whitelists})

	err = c.LocalDB.SetWhitelists(whitelists)
	if err != nil {
		return fmt.Errorf("set whitelists: %s", err)
	}
	c.Logger.Info("set-whitelist-success")

	return nil
}
