package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
)

// API serves HTTP endpoints for peer health data.
type API struct {
	server *Server
}

type statsResponse struct {
	TotalPeers     int    `json:"total_peers"`
	ConnectedPeers int    `json:"connected_peers"`
	BestBlock      uint64 `json:"best_block"`
	DHTPoolSize    int    `json:"dht_pool_size"`
}

// StartAPI starts the HTTP API server on the given address.
func StartAPI(addr string, srv *Server) {
	api := &API{server: srv}

	mux := http.NewServeMux()
	mux.HandleFunc("/peers", api.handlePeers)
	mux.HandleFunc("/stats", api.handleStats)
	mux.HandleFunc("/peers/export", api.handleExport)

	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil {
			fmt.Printf("[api] HTTP server error: %v\n", err)
		}
	}()
}

func (a *API) handlePeers(w http.ResponseWriter, r *http.Request) {
	peers := a.server.store.AllPeers()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(peers)
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	dhtSize := 0
	if a.server.discovery != nil {
		dhtSize = a.server.discovery.PoolSize()
	}

	stats := statsResponse{
		TotalPeers:     a.server.store.TotalCount(),
		ConnectedPeers: a.server.store.ConnectedCount(),
		BestBlock:      a.server.store.BestBlock(),
		DHTPoolSize:    dhtSize,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (a *API) handleExport(w http.ResponseWriter, r *http.Request) {
	minScore := 0.0
	if v := r.URL.Query().Get("min_score"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			minScore = f
		}
	}

	peers := a.server.store.AllPeers()
	var enodes []string
	for _, p := range peers {
		if p.Score >= minScore && p.Enode != "" {
			enodes = append(enodes, p.Enode)
		}
	}

	if enodes == nil {
		enodes = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enodes)
}
