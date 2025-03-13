package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/StackVista/stackstate-process-agent/cmd/agent/features"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/httpclient"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/model/check"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/model/telemetry"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/model/topology"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionbatcher"
	"github.com/StackVista/stackstate-receiver-go-client/pkg/transactional/transactionmanager"
	"github.com/gofrs/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"reflect"
	"sync/atomic"
	"time"

	log "github.com/cihub/seelog"

	"github.com/StackVista/stackstate-process-agent/checks"
	"github.com/StackVista/stackstate-process-agent/config"
	"github.com/StackVista/stackstate-process-agent/model"
)

var agentTopologyInstance = topology.Instance{
	Type: "agent",
	URL:  "integrations",
}

type checkResult struct {
	check   checks.Check
	err     error
	payload *checkPayload
}

type checkPayload struct {
	messages  []model.MessageBody
	metrics   []telemetry.RawMetric
	endpoint  string
	timestamp time.Time
}

// Collector will collect metrics from the local system and ship to the backend.
type Collector struct {
	send          chan checkResult
	cfg           *config.AgentConfig
	groupID       int32
	runCounter    int32
	enabledChecks []checks.Check
	features      features.Features

	batcher transactionbatcher.TransactionalBatcher
	manager transactionmanager.TransactionManager
	client  *httpclient.StackStateClient
}

// NewCollector creates a new Collector
func NewCollector(cfg *config.AgentConfig,
	client *httpclient.StackStateClient,
	batcher transactionbatcher.TransactionalBatcher,
	manager transactionmanager.TransactionManager) (Collector, error) {
	sysInfo, err := checks.CollectSystemInfo()
	if err != nil {
		return Collector{}, err
	}

	enabledChecks := make([]checks.Check, 0)
	for _, c := range checks.All {
		if cfg.CheckIsEnabled(c.Name()) {
			err = c.Init(cfg, sysInfo)
			if err != nil {
				return Collector{}, fmt.Errorf("failed to intialize check %s: %w", c.Name(), err)
			}
			enabledChecks = append(enabledChecks, c)
		}
	}

	return Collector{
		send:          make(chan checkResult, cfg.QueueSize),
		cfg:           cfg,
		groupID:       rand.Int31(),
		enabledChecks: enabledChecks,
		features:      features.Empty(),

		batcher: batcher,
		manager: manager,
		client:  client,
	}, nil
}

var (
	checkRunDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "stackstate_process_agent",
		Subsystem: "checks",
		Name:      "run_duration",
		Help:      "How long time it took to check to run, in seconds",
	}, []string{"check"})
)

func (l *Collector) runCheck(c checks.Check, features features.Features) {
	runCounter := atomic.AddInt32(&l.runCounter, 1)
	currentTime := time.Now()
	// update the last collected timestamp for info
	updateLastCollectTime(currentTime)
	result, err := c.Run(l.cfg, features, atomic.AddInt32(&l.groupID, 1), currentTime)
	checkRunDuration.WithLabelValues(c.Name()).Observe(time.Since(currentTime).Seconds())

	switch {
	case err != nil && result == nil:
		// if we don't have a result, we can't send anything to the backend
		l.send <- checkResult{check: c, err: err}
		log.Criticalf("Unable to run check '%s': %s", c.Name(), err)
		return
	case err == nil && result == nil:
		log.Infof("Ignoring empty result of '%s' check", c.Name())
	case err != nil && result != nil, err == nil && result != nil:
		// If we have an error we print a warning and send the result anyway
		if err != nil {
			log.Warnf("Check '%s' partially failed: %v", c.Name(), err)
		}
		l.send <- checkResult{
			check:   c,
			payload: &checkPayload{result.CollectorMessages, result.Metrics, c.Endpoint(), currentTime},
			err:     err,
		}
		// update proc and container count for info
		updateProcContainerCount(result.CollectorMessages)
	}

	d := time.Since(currentTime)
	switch {
	case runCounter < 5:
		log.Infof("Finished check #%d in %s", runCounter, d)
	case runCounter == 5:
		log.Infof("Finished check #%d in %s. First 5 check runs finished, next runs will be logged every 20 runs.", runCounter, d)
	case runCounter%20 == 0:
		log.Infof("Finish check #%d in %s", runCounter, d)
	}
}

func (l *Collector) run(exit chan bool) {
	eps := make([]string, 0, len(l.cfg.APIEndpoints))
	for _, e := range l.cfg.APIEndpoints {
		eps = append(eps, e.Endpoint.String())
	}
	log.Infof("Starting process-agent for host=%s, endpoints=%s, enabled checks=%v", l.cfg.HostName, eps, l.cfg.EnabledChecks)

	go handleSignals(exit)
	queueSizeTicker := time.NewTicker(10 * time.Second)
	featuresTicker := time.NewTicker(5 * time.Second)

	// Channel to announce new features detected
	featuresCh := make(chan features.Features, 1)

	// We poll the features a first time. We will try several times until we receive a response.
	// So these features cannot change over time, Why don't we provide them into the helm chat instead of using this polling?
	l.getFeatures(l.cfg.APIEndpoints[0], "/features", featuresCh)

	go func() {
		for {
			select {
			case result := <-l.send:
				if len(l.send) >= l.cfg.QueueSize {
					log.Info("Expiring payload from in-memory queue.")
					// Limit number of items kept in memory while we wait.
					<-l.send
				}

				checkID := check.CheckID(result.check.Name())
				transactionUID, err := uuid.NewV4()

				if err != nil {
					log.Errorf("Error creating transaction id: %s", err.Error())
					break
				}

				transactionID := transactionUID.String()

				txOut := make(chan interface{})

				l.manager.StartTransaction(checkID, transactionID, txOut)
				l.batcher.StartTransaction(checkID, transactionID)

				// create a new transaction in the transaction manager and wait for responses

				if result.payload != nil {
					payload := result.payload
					for _, m := range payload.messages {
						l.postMessage(payload.endpoint, m, payload.timestamp)
					}

					for _, metric := range payload.metrics {
						l.batcher.SubmitRawMetricsData(checkID, transactionID, metric)
					}
				}

				if l.cfg.ReportCheckHealthState || l.features.FeatureEnabled(features.HealthStates) {
					healthStream, healthData := l.makeHealth(result)

					repeatInterval := int(l.cfg.CheckInterval(result.check.Name()).Seconds())
					l.batcher.SubmitHealthStartSnapshot(checkID, transactionID, healthStream, repeatInterval, repeatInterval*4)
					l.batcher.SubmitHealthCheckData(checkID, transactionID, healthStream, healthData)
					l.batcher.SubmitHealthStopSnapshot(checkID, transactionID, healthStream)
				}

				l.batcher.SubmitCompleteTransaction(checkID, transactionID)

				// Wait for the transaction response. We are not too interested in handling transaction errors right now
				<-txOut
				close(txOut)
			case <-queueSizeTicker.C:
				updateQueueSize(l.send)
			case <-featuresTicker.C:
				l.getFeatures(l.cfg.APIEndpoints[0], "/features", featuresCh)
			case featuresValue := <-featuresCh:
				l.features = featuresValue
				// Stop polling
				featuresTicker.Stop()
			case <-exit:
				return
			}
		}
	}()

	for _, c := range l.enabledChecks {
		// Assignment here, because iterator value gets altered
		go func(c checks.Check) {
			// Run the check the first time to prime the caches.
			l.runCheck(c, l.features)

			ticker := time.NewTicker(l.cfg.CheckInterval(c.Name()))
			for {
				select {
				case <-ticker.C:
					l.runCheck(c, l.features)
				case _, ok := <-exit:
					if !ok {
						return
					}
				}
			}
		}(c)
	}
	<-exit
}

func (l *Collector) postMessage(checkPath string, m model.MessageBody, timestamp time.Time) {
	msgType, err := model.DetectMessageType(m)
	if err != nil {
		log.Errorf("Unable to detect message type: %s", err)
		return
	}

	body, err := model.EncodeMessage(model.Message{
		Header: model.MessageHeader{
			Version:   model.MessageV3,
			Encoding:  model.MessageEncodingZstdPB,
			Type:      msgType,
			Timestamp: timestamp.UnixNano() / int64(time.Millisecond),
		}, Body: m})

	if err != nil {
		log.Errorf("Unable to encode message: %s", err)
	}

	responses := make(chan errorResponse)
	for _, ep := range l.cfg.APIEndpoints {
		go l.postToAPI(ep, checkPath, body, responses)
	}

	// Wait for all responses to come back before moving on.
	statuses := make([]*model.CollectorStatus, 0, len(l.cfg.APIEndpoints))
	for i := 0; i < len(l.cfg.APIEndpoints); i++ {
		res := <-responses
		if res.err != nil {
			log.Error(res.err)
			continue
		}
	}

	if len(statuses) > 0 {
		l.updateStatus(statuses)
	}
}

func (l *Collector) updateStatus(statuses []*model.CollectorStatus) {
	// If any of the endpoints wants real-time we'll do that.
	// We will pick the maximum interval given since generally this is
	// only set if we're trying to limit load on the backend.
	maxInterval := 0 * time.Second
	for _, s := range statuses {
		interval := time.Duration(s.Interval) * time.Second
		if interval > maxInterval {
			maxInterval = interval
		}
	}
}

type errorResponse struct {
	err error
}

func (l *Collector) postToAPI(endpoint config.APIEndpoint, checkPath string, body []byte, responses chan errorResponse) {
	l.postToAPIwithEncoding(endpoint, checkPath, body, responses, "x-zip")
}

func (l *Collector) postToAPIwithEncoding(endpoint config.APIEndpoint, checkPath string, body []byte, responses chan errorResponse, contentEncoding string) {
	resp, err := l.accessAPIwithEncoding(endpoint, "POST", checkPath, body, contentEncoding)
	if err != nil {
		responses <- errorResponse{err: err}
		return
	}
	defer resp.Body.Close()
	responses <- errorResponse{nil}
}

func (l *Collector) getFeatures(endpoint config.APIEndpoint, checkPath string, report chan features.Features) {
	resp, accessErr := l.accessAPIwithEncoding(endpoint, "GET", checkPath, make([]byte, 0), "identity")

	// Handle error response
	if accessErr != nil {
		// Soo we got a 404, meaning we were able to contact stackstate, but it had no features path. We can publish a result
		if resp != nil {
			log.Info("Found StackState version which does not support feature detection yet")
			report <- features.Empty()
			return
		}
		// Log
		_ = log.Error(accessErr)
		return
	}

	defer resp.Body.Close()

	// Get byte array
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		_ = log.Errorf("could not decode response body from features: %s", err)
		return
	}
	var data interface{}
	// Parse json
	err = json.Unmarshal(body, &data)
	if err != nil {
		_ = log.Errorf("error unmarshalling features json: %s of body %s", err, body)
		return
	}

	// Validate structure
	featureMap, ok := data.(map[string]interface{})
	if !ok {
		_ = log.Errorf("Json was wrongly formatted, expected map type, got: %s", reflect.TypeOf(data))
	}

	featuresParsed := make(map[features.FeatureID]bool)

	for k, v := range featureMap {
		featureValue, okV := v.(bool)
		if !okV {
			_ = log.Warnf("Json was wrongly formatted, expected boolean type, got: %s, skipping feature %s", reflect.TypeOf(v), k)
		}
		featuresParsed[features.FeatureID(k)] = featureValue
	}

	log.Infof("Server supports features: %s", featuresParsed)
	report <- features.Make(featuresParsed)
}

func (l *Collector) accessAPIwithEncoding(endpoint config.APIEndpoint, method string, checkPath string, body []byte, contentEncoding string) (*http.Response, error) {
	url := endpoint.Endpoint.String() + checkPath // Add the checkPath in full Process Agent URL
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("could not create %s request to %s: %s", method, url, err)
	}

	req.Header.Add("content-encoding", contentEncoding)
	req.Header.Add("sts-api-key", endpoint.APIKey)
	req.Header.Add("sts-hostname", l.cfg.HostName)
	req.Header.Add("sts-processagentversion", Version)

	ctx, cancel := context.WithTimeout(context.Background(), ReqCtxTimeout)
	defer cancel()
	req.WithContext(ctx)

	log.Debugf("Sent payload, size: %d bytes.", len(body))
	resp, err := l.client.GetClient().Do(req)
	if err != nil {
		if isHTTPTimeout(err) {
			return nil, fmt.Errorf("Timeout detected on %s, %s", url, err)
		}
		return nil, fmt.Errorf("Error submitting payload to %s: %s", url, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 300 {
		defer resp.Body.Close()
		io.Copy(ioutil.Discard, resp.Body)
		return resp, fmt.Errorf("unexpected response from %s. Status: %s, Body: %v", url, resp.Status, resp.Body)
	}
	log.Debugf("Response from %s is %d", url, resp.StatusCode)

	return resp, nil

}
