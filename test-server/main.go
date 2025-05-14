package main

import (
	"context"
	"encoding/json"
	"fmt"
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
	configEnvVar      = "CONFIG_PATH"
	defaultConfigPath = "config.json"
)

var (
	cfg *Config
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

		for _, c := range collectorConn.Connections {
			if c.ApplicationProtocol == config.PostgresProtocolName {
				jsonConn, err := json.MarshalIndent(c, "", "  ")
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
			}
		}

		// jsonConn, err := json.MarshalIndent(collectorConn, "", "  ")
		// if err != nil {
		// 	log.Println("cannot serialize JSON:", err)
		// 	return
		// }

		// fileMutex.Lock()
		// _, err = file.Write(jsonConn)
		// fileMutex.Unlock()
		// if err != nil {
		// 	log.Println("cannot write Json to file:", err)
		// 	return
		// }

		newCount := atomic.AddInt32(&requestCount, 1)
		log.Printf("Request received, count: %d", newCount)
		if newCount >= int32(cfg.RequestCount) {
			log.Printf("Maximum number of requests (%d) reached, triggering shutdown", cfg.RequestCount)
			select {
			case shutdownChan <- false:
			default:
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func loadConfig() (*Config, error) {
	envPath := os.Getenv(configEnvVar)
	if envPath == "" {
		envPath = defaultConfigPath
	}

	f, err := os.Open(envPath)
	if err != nil {
		return nil, fmt.Errorf("cannot open config at '%s': %w", envPath, err)
	}
	defer f.Close()

	var cfg Config
	decoder := json.NewDecoder(f)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("cannot decode JSON config: %w", err)
	}
	return &cfg, nil
}

func run() bool {
	err := os.MkdirAll(filepath.Dir(cfg.OutputFile), 0755)
	if err != nil {
		log.Fatalf("Error creating directory: %v\n", err)
	}

	file, err = os.OpenFile(cfg.OutputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
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
		Addr:    cfg.Server.Host + ":" + cfg.Server.Port,
		Handler: mux,
	}

	go func() {
		log.Printf("Server listening on port %s...", cfg.Server.Port)
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

// todo!: manage logging...
// todo!: use Viper for the config
func main() {
	var err error
	cfg, err = loadConfig()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	match := run()
	if match {
		log.Println("Shutdown triggered by match")
	} else {
		// this will return os.Exit(1)
		log.Fatal("Cannot find a match, shutting down")
	}
}
