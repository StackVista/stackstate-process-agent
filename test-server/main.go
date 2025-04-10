package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
)

const (
	// Maximum number of requests after which the server will shut down
	maxRequests    = 100
	port           = "7077"
	outputFilePath = "./output/output.json"
)

var (
	// Counter for received requests (using atomic operations for thread safety)
	requestCount int32

	// Mutex to protect concurrent file writes
	fileMutex sync.Mutex

	// Channel to signal a shutdown request
	// We send `true` to the channel if we find a match
	// We send `false` if we reach the max requests
	shutdownChan = make(chan bool)

	file *os.File
)

func genericHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s", r.Method, r.URL.Path)
	w.WriteHeader(http.StatusOK)
}

func stopHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received STOP request: %s %s", r.Method, r.URL.Path)
	select {
	case shutdownChan <- true:
	default:
	}
	w.WriteHeader(http.StatusOK)
}

func dumpData(w http.ResponseWriter, r *http.Request) {
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

	// At the moment we just want to dump the connection messages
	switch m.Body.(type) {
	case *model.CollectorConnections:
		collectorConn := m.Body.(*model.CollectorConnections)

		jsonConn, err := json.MarshalIndent(collectorConn, "", "  ")
		if err != nil {
			log.Println("cannot serialize JSON:", err)
			return
		}

		fileMutex.Lock()
		_, err = file.Write(jsonConn)
		fileMutex.Unlock()
		if err != nil {
			log.Println("cannot write Json to file:", err)
			return
		}

		// check if we need to terminate
		// todo!: we need to validate when we find a particular Json
		for _, c := range collectorConn.Connections {
			if c.ApplicationProtocol == config.PostgresProtocolName {
				if len(c.GetMetrics()) > 1 {
					v, ok := c.GetMetrics()[0].GetTags()["database"]
					if !ok || v != "demo" {
						continue
					}
					v, ok = c.GetMetrics()[0].GetTags()["command"]
					if !ok || v != "SELECT" {
						continue
					}
					log.Println("Desired data received, triggering shutdown")
					select {
					case shutdownChan <- true:
					default:
					}
				}
			}
		}

		newCount := atomic.AddInt32(&requestCount, 1)
		log.Printf("Request received, count: %d", newCount)
		if newCount >= maxRequests {
			log.Printf("Maximum number of requests (%d) reached, triggering shutdown", maxRequests)
			select {
			case shutdownChan <- false:
			default:
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func run() bool {

	// Clear the request count
	requestCount = 0

	// todo!: add a configuration file to configure the server
	// todo!: manage logging...
	var err error
	err = os.MkdirAll(filepath.Dir(outputFilePath), 0755)
	if err != nil {
		log.Fatalf("Error creating directory: %v\n", err)
	}

	file, err = os.OpenFile(outputFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}

	defer func() {
		file.Write([]byte("]"))
		file.Close()
	}()

	// Start the JSON array
	_, err = file.Write([]byte("["))
	if err != nil {
		log.Fatalf("Error writing to file: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stsAgent/api/v1/connections", dumpData)
	mux.HandleFunc("/stsAgent/stop", stopHandler)
	mux.HandleFunc("/stsAgent/", genericHandler)

	// Configure the HTTP server
	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		log.Printf("Server listening on port %s...", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Error while running the server: %v", err)
		}
	}()

	match := <-shutdownChan
	log.Println("Server shutdown in progress...")

	// Perform graceful shutdown with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Error during server shutdown: %v", err)
	}
	log.Println("Server terminated successfully")
	return match
}

func main() {
	match := run()
	if match {
		log.Println("Shutdown triggered by match")
	} else {
		// this will return os.Exit(1)
		log.Fatal("Cannot find a match, shutting down")
	}
}
