package xdc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type PeerInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Network struct {
		LocalAddress  string `json:"localAddress"`
		RemoteAddress string `json:"remoteAddress"`
	} `json:"network"`
}

type RPCResponse struct {
	ID      int        `json:"id"`
	JSONRPC string     `json:"jsonrpc"`
	Result  []PeerInfo `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func GetPeers(rpcURL string) ([]PeerInfo, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "admin_peers",
		"params":  []interface{}{},
		"id":      1,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(rpcURL, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rpcResp RPCResponse
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, err
	}

	if rpcResp.Error != nil {
		return nil, fmt.Errorf("RPC error: %s", rpcResp.Error.Message)
	}

	return rpcResp.Result, nil
}
