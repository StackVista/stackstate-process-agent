package main

import (
	"encoding/json"
	"github.com/StackVista/stackstate-process-agent/model"
	"io"
	"log"
	"net/http"
)

// FeaturesResponse Empty feature set to send
type FeaturesResponse struct {
}

// Handler for GET /stsAgent/features
func featuresHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.Path)
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(FeaturesResponse{})
}

func genericHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.Path)
	w.WriteHeader(http.StatusOK)
}

func decodeMessage(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.Path)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	m, err := model.DecodeMessage(body)
	if err != nil {
		http.Error(w, "Error deconding message body", http.StatusBadRequest)
		return
	}

	switch m.Body.(type) {
	case *model.CollectorConnections:
		collectorConn := m.Body.(*model.CollectorConnections)
		for _, c := range collectorConn.Connections {
			if c.ApplicationProtocol == "postgres" {
				log.Printf("[%s]Pid: %d, Netns: %d, laddr %s, lport %d, raddr %s, rport %d", c.ApplicationProtocol, c.Pid, c.NetNs, c.GetLaddr().GetIp(), c.GetLaddr().GetPort(), c.GetRaddr().GetIp(), c.GetRaddr().GetPort())
				for _, m := range c.GetMetrics() {
					log.Printf("- Metric: name %s, value %s, tag %s", m.GetName(), m.GetValue().String(), m.GetTags())
				}
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func printHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.Path)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/stsAgent/features", featuresHandler)
	mux.HandleFunc("/stsAgent/api/v1/connections", decodeMessage)
	mux.HandleFunc("/stsAgent/intake", printHandler)
	mux.HandleFunc("/stsAgent/", genericHandler)

	port := "7077"
	log.Printf("Server listening on port %s...", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Error starting the server: %v", err)
	}
}
