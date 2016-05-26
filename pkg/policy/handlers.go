package policy

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/pivotal-golang/lager"
)

type Handler struct {
	Logger          lager.Logger
	LocalListenAddr string
	Registrar       EndpointCollection
}

func (c *Handler) RunServer() error {
	c.Logger.Info("run-server", lager.Data{"listen": c.LocalListenAddr})
	err := http.ListenAndServe(c.LocalListenAddr, c.getHandler())
	return err
}

type payload struct {
	ContainerID string
	Result      struct {
		IP4 struct {
			IP string
		}
	}
	Config struct {
		Bytes []byte
	}
}

type configPayload struct {
	Network struct {
		Properties struct {
			AppID   string `json:"app_id"`
			SpaceID string `json:"space_id"`
			OrgID   string `json:"org_id"`
		}
	}
}

func readPayload(body io.Reader) (Endpoint, error) {
	payloadBytes, err := ioutil.ReadAll(body)
	if err != nil {
		return Endpoint{}, err
	}
	var pp payload
	err = json.Unmarshal(payloadBytes, &pp)
	if err != nil {
		return Endpoint{}, err
	}
	var ip net.IP
	if pp.Result.IP4.IP != "" {
		ip, _, err = net.ParseCIDR(pp.Result.IP4.IP)
		if err != nil {
			return Endpoint{}, err
		}
	}
	var confPayload configPayload
	err = json.Unmarshal(pp.Config.Bytes, &confPayload)
	if err != nil {
		return Endpoint{}, err
	}
	return Endpoint{
		ContainerID: pp.ContainerID,
		GroupID:     confPayload.Network.Properties.AppID,
		OverlayIP:   ip,
	}, nil
}

func (h *Handler) addResultHandler(resp http.ResponseWriter, req *http.Request) {
	logger := h.Logger.Session("add-result-handler")
	logger.Info("start")
	defer logger.Info("done")

	endpoint, err := readPayload(req.Body)
	if err != nil {
		logger.Error("read-payload", err)
		resp.WriteHeader(http.StatusBadRequest)
		return
	}
	logger.Info("got-payload", lager.Data{"endpoint": endpoint})
	err = h.Registrar.Register(endpoint)
	if err != nil {
		logger.Error("register", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp.WriteHeader(http.StatusOK)
}

func (h *Handler) delResultHandler(resp http.ResponseWriter, req *http.Request) {
	logger := h.Logger.Session("del-result-handler")
	logger.Info("start")
	defer logger.Info("done")

	endpoint, err := readPayload(req.Body)
	if err != nil {
		logger.Error("read-payload", err)
		resp.WriteHeader(http.StatusBadRequest)
		return
	}
	logger.Info("got-payload", lager.Data{"endpoint": endpoint})
	err = h.Registrar.Deregister(endpoint)
	if err != nil {
		logger.Error("deregister", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}
	resp.WriteHeader(http.StatusOK)
}

func (h *Handler) getHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/cni-result/add", http.HandlerFunc(h.addResultHandler))
	mux.Handle("/cni-result/del", http.HandlerFunc(h.delResultHandler))
	return mux
}
