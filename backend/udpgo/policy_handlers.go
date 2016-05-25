package udpgo

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/pivotal-golang/lager"
)

type PolicyControl struct {
	Logger          lager.Logger
	LocalListenAddr string
}

func (c *PolicyControl) Run() error {
	c.Logger.Info("run", lager.Data{"listen": c.LocalListenAddr})
	err := http.ListenAndServe(c.LocalListenAddr, c.getHandler())
	return err
}

type PolicyPayload struct {
	Result struct {
		IP4 struct {
			IP string
		}
	}
	Config struct {
		Bytes []byte
	}
}

type PolicyConfigPayload struct {
	Network struct {
		Properties struct {
			AppID   string `json:"app_id"`
			SpaceID string `json:"space_id"`
			OrgID   string `json:"org_id"`
		}
	}
}

func readPayload(body io.Reader) (string, net.IP, error) {
	payloadBytes, err := ioutil.ReadAll(body)
	if err != nil {
		return "", nil, err
	}
	var pp PolicyPayload
	err = json.Unmarshal(payloadBytes, &pp)
	if err != nil {
		return "", nil, err
	}
	var ip net.IP
	if pp.Result.IP4.IP != "" {
		ip, _, err = net.ParseCIDR(pp.Result.IP4.IP)
		if err != nil {
			return "", nil, err
		}
	}
	var confPayload PolicyConfigPayload
	err = json.Unmarshal(pp.Config.Bytes, &confPayload)
	if err != nil {
		return "", nil, err
	}
	return confPayload.Network.Properties.AppID, ip, nil
}

func (h *PolicyControl) addResultHandler(resp http.ResponseWriter, req *http.Request) {
	logger := h.Logger.Session("add-result-handler")
	logger.Info("start")
	defer logger.Info("done")

	appID, ip, err := readPayload(req.Body)
	if err != nil {
		logger.Error("read-payload", err)
		return
	}
	logger.Info("got-payload", lager.Data{"ip": ip, "app_id": appID})
	resp.WriteHeader(http.StatusOK)
}

func (h *PolicyControl) delResultHandler(resp http.ResponseWriter, req *http.Request) {
	logger := h.Logger.Session("del-result-handler")
	logger.Info("start")
	defer logger.Info("done")

	appID, _, err := readPayload(req.Body)
	if err != nil {
		logger.Error("read-payload", err)
		return
	}
	logger.Info("got-payload", lager.Data{"app_id": appID})
	resp.WriteHeader(http.StatusOK)
}

func (h *PolicyControl) getHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/cni-result/add", http.HandlerFunc(h.addResultHandler))
	mux.Handle("/cni-result/del", http.HandlerFunc(h.delResultHandler))
	return mux
}
