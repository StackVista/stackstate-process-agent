package main

import (
	"encoding/json"
	// "github.com/StackVista/agent-transport-protocol/pkg/model"
	// "github.com/StackVista/stackstate-process-agent/model"
	// "io"
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

func printHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.Path)
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// body, err := io.ReadAll(r.Body)
	// if err != nil {
	// 	http.Error(w, "Error reading request body", http.StatusInternalServerError)
	// 	return
	// }

	// m, err := model.DecodeMessage(body)
	// if err != nil {
	// 	http.Error(w, "Error deconding message body", http.StatusBadRequest)
	// 	return
	// }

	// log.Printf("Body: %s", m.Body.String())
	w.WriteHeader(http.StatusOK)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/stsAgent/features", featuresHandler)
	mux.HandleFunc("/stsAgent/api/v1/connections", printHandler)
	mux.HandleFunc("/stsAgent/intake", printHandler)
	mux.HandleFunc("/stsAgent/", genericHandler)

	port := "7077"
	log.Printf("Server listening on port %s...", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("Error starting the server: %v", err)
	}
}
