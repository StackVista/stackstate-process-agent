
SETUP_TIMEOUT ?= 120s
SETUP_AGENT_HELM_CHART_DIR ?= ~/personal/helm-charts/stable/suse-observability-agent

# SETUP_TYPE can be 'local' or 'remote' (default: local)
SETUP_TYPE ?= local
SETUP_API_KEY ?= null
SETUP_CLUSTER_NAME ?= minikube-local-setup
SETUP_RECEIVER_ENDPOINT ?= http://test-server-service:7077/stsAgent
# To be set only in remote mode
SETUP_OTEL_ENDPOINT ?= null

.PHONY: create-cluster
create-cluster:
	@echo "🚀 Creating Kubernetes cluster..."
	minikube start --driver=kvm2 --cpus=6 --memory=12g --disk-size='30g' 

.PHONY: delete-cluster
delete-cluster:
	@echo "🧹 Deleting Kubernetes cluster..."
	minikube delete

.PHONY: load-agent-image
load-agent-image:
	@echo "🚀 Loading agent image into the cluster..."
# we should also build again the ebpf probes but at the moment we skip it since we suppose we are in the middle of the development
	rake local_build
	docker build --tag registry/agent:latest -f ../Dockerfile ..
	minikube image rm registry/agent:latest 2>/dev/null || true
	minikube image load registry/agent:latest

.PHONY: load-test-server-image
load-test-server-image:
	@echo "🚀 Loading test server image into the cluster..."
	go build -o ../test-server ../test-server
	docker build --tag test-server:latest -f ../test-server/Dockerfile ../test-server
	minikube image rm test-server:latest 2>/dev/null || true
	minikube image load test-server:latest

.PHONY: deploy-prometheus
deploy-prometheus:
	@echo "🚀 Deploying Prometheus..."
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	helm upgrade --install --wait --timeout $(SETUP_TIMEOUT) prometheus prometheus-community/prometheus --version 27.32.0 \
  		--values ./yaml/prometheus-config.yaml \
  		--namespace open-telemetry --create-namespace

.PHONY: deploy-test-server
deploy-test-server: load-test-server-image
	@echo "🚀 Deploying the test server in monitoring namespace..."
	kubectl create namespace monitoring || true
	kubectl apply -f ./yaml/test-server.yaml -n monitoring
	@echo "🕐 Waiting for test-server..."
	kubectl wait --for=condition=Ready -n monitoring pod -l app=test-server --timeout=$(SETUP_TIMEOUT)

.PHONY: deploy-otel-collector
deploy-otel-collector:
	@echo "🚀 Deploying OTEL collector ($(SETUP_TYPE))..."
# We need to create the secret and configMap for the remote setup so that the OTEL collector configuration can use them
	if [ "$(SETUP_TYPE)" = "remote" ]; then \
		kubectl create namespace open-telemetry || true; \
		kubectl create secret generic open-telemetry-collector --namespace open-telemetry --from-literal=SETUP_API_KEY="$(SETUP_API_KEY)"; \
		kubectl create configmap open-telemetry-collector-config --namespace open-telemetry \
			--from-literal=SETUP_CLUSTER_NAME="$(SETUP_CLUSTER_NAME)" \
			--from-literal=SETUP_OTEL_ENDPOINT="$(SETUP_OTEL_ENDPOINT)"; \
	fi
	helm repo add open-telemetry https://open-telemetry.github.io/opentelemetry-helm-charts
	helm upgrade --install --wait --timeout $(SETUP_TIMEOUT) opentelemetry-collector open-telemetry/opentelemetry-collector --version 0.132.0 \
		--values ./yaml/otel-collector-config-$(SETUP_TYPE).yaml \
		--namespace open-telemetry --create-namespace

.PHONY: deploy-agent
deploy-agent: load-agent-image
	@echo "🚀 Deploying the process agent ($(SETUP_TYPE))..."
	helm upgrade --install --devel\
		suse-observability-agent \
		$(SETUP_AGENT_HELM_CHART_DIR) \
		--set-string 'stackstate.apiKey'='$(SETUP_API_KEY)' \
		--set-string 'stackstate.cluster.name'='$(SETUP_CLUSTER_NAME)' \
		--set-string 'stackstate.url'='$(SETUP_RECEIVER_ENDPOINT)' \
		--set logsAgent.enabled=false \
		--set clusterAgent.enabled=false \
		--set checksAgent.enabled=false \
		--set kubernetes-rbac-agent.enabled=false \
		--set processAgent.podCorrelation.enabled=true \
		--set processAgent.podCorrelation.protocolMetrics=true \
		--set nodeAgent.httpTracing.enabled=false \
		--set-string processAgent.podCorrelation.exporter.type=otlp \
		--set-string processAgent.podCorrelation.exporter.endpoint=opentelemetry-collector.open-telemetry.svc.cluster.local:4317 \
		--namespace monitoring \
		--create-namespace \
		--set-string 'nodeAgent.skipKubeletTLSVerify'='true' \
		--set-string 'nodeAgent.containers.processAgent.image.pullPolicy'='Never' \
		--set-string 'nodeAgent.containers.processAgent.image.tag'='latest' \
		--set-string 'nodeAgent.containers.processAgent.image.registry'='registry' \
		--set-string 'nodeAgent.containers.processAgent.image.repository'='agent'

.PHONY: deploy
deploy: deploy-prometheus deploy-otel-collector deploy-agent
	@if [ "$(SETUP_TYPE)" = "local" ]; then $(MAKE) deploy-test-server; fi
	@echo "✅ Completed deploy (mode=$(SETUP_TYPE))"

.PHONY: redeploy-agent
redeploy-agent:
	@echo "🚀 Removing old agent chart..."
	helm uninstall suse-observability-agent -n monitoring || true
	@echo "🚀 Redeploying the process-agent ($(SETUP_TYPE))..."
	$(MAKE) deploy-agent
	@echo "✅ Completed re-deploy (mode=$(SETUP_TYPE))"

# Obtain a local copy of the json output from the test server pod
# useful only with legacy metrics
.PHONY: take-output
take-output:
	if [ "$(SETUP_TYPE)" = "remote" ]; then return; fi
	@echo "📄 Dump output file..."
	kubectl cp -n monitoring $$(kubectl get -n monitoring pods -l app=test-server -o custom-columns=:metadata.name --no-headers):output.json ./output.json

############################
# End-to-end tests targets #
############################
.PHONY: deploy-e2e-tests
deploy-e2e-tests:
	@echo "🚀 Deploying Postgres service..."
	kubectl apply -f ./yaml/postgres.yaml
	kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=postgres-server --timeout=$(SETUP_TIMEOUT)
	kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=postgres-client --timeout=$(SETUP_TIMEOUT)

.PHONY: run-e2e-tests
run-e2e-tests:
	@echo "🚀 Running end-to-end tests..."
	go test -count=1 -tags 'docker kubelet kubeapiserver linux cri containerd linux_bpf k8s_e2e' ./tests -v

.PHONY: clean-e2e-tests
clean-e2e-tests:
	kubectl delete -f ./yaml/postgres.yaml
