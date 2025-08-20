
NAMESPACE := default
DST_DIR   := /suse

.PHONY: deploy
deploy:
	@echo "🚀 Deploying the process-agent and basic components in namespace '$(NAMESPACE)'..."
	kubectl apply -f ./yaml/deployment.yaml -n $(NAMESPACE)
	@echo "🚀 Deploying the Postgres service in namespace '$(NAMESPACE)'..."
	kubectl apply -f ./yaml/postgres.yaml -n $(NAMESPACE)
	@echo "🕐 Waiting for necessary components to be up..."
	kubectl wait --for=condition=Ready pod -l app=loader-agent --timeout=180s
	kubectl wait --for=condition=Ready pod -l app=opentelemetry --timeout=180s
	kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=prometheus --timeout=180s
	@echo "🕐 Waiting for postgres service to be up..."
	kubectl wait --for=condition=Ready pod -l app=postgres-client --timeout=180s
	kubectl wait --for=condition=Ready pod -l app=postgres-server --timeout=180s

.PHONY: update
# Substitute all the binaries and config files inside the dockers
# NOTE: kubectl cp will overwrite the previous files.
update:
	@echo "🔄 Updating binaries inside pods..."
	for loader_pod in $$(kubectl get pods -n ${NAMESPACE} -l app=loader-agent -o custom-columns=:metadata.name --no-headers); do \
			echo "=> Considering pod: $${loader_pod}"; \
			echo "  [1/6] Copying process-agent binary..."; \
			kubectl cp "../process-agent" ${NAMESPACE}/$${loader_pod}:"${DST_DIR}/process-agent"; \
			echo "  [2/6] Copying process-agent config..."; \
			kubectl cp "./process-agent-config.yaml" ${NAMESPACE}/$${loader_pod}:"${DST_DIR}/config.yaml"; \
			echo "  [3/6] Creating directory for 'ebpf-object-files'..."; \
			kubectl exec -n ${NAMESPACE} $${loader_pod} -- mkdir -p "${DST_DIR}/ebpf-object-files/"; \
			echo "  [4/6] Copying 'ebpf-object-files/x86_64'..."; \
			kubectl cp "../ebpf-object-files/x86_64" ${NAMESPACE}/$${loader_pod}:"${DST_DIR}/ebpf-object-files/"; \
			echo "  [5/6] Copying test-server binary..."; \
			kubectl cp "../test-server/test-server" ${NAMESPACE}/$${loader_pod}:"${DST_DIR}/test-server"; \
			echo "  [5/6] Copying test-server config..."; \
			kubectl cp "./test-server-config.json" ${NAMESPACE}/$${loader_pod}:"${DST_DIR}/config.json"; \
	done; \
	echo "🧹 Deleting pods..."; \
	kubectl delete pods -n ${NAMESPACE} -l app=process-agent --force
	kubectl delete pods -n ${NAMESPACE} -l app=test-server --force
	@echo "🕐 Waiting for process-agent to be up..."
	kubectl wait --for=condition=Ready pod -l app=process-agent --timeout=180s
	@echo "🕐 Waiting for test-server to be up..."
	kubectl wait --for=condition=Ready pod -l app=test-server --timeout=180s


.PHONY: e2e-tests
e2e-tests:
	@echo "🚀 Running end-to-end tests..."
	go test -tags 'test docker kubelet kubeapiserver linux cri containerd linux_bpf k8s_e2e' ./tests -v

# Obtain a local copy of the json output from the test server pod
# useful only with legacy metrics
.PHONY: take-output
take-output:
	@echo "📄 Dump output file..."; \
	kubectl cp $$(kubectl get pods -l app=test-server -o custom-columns=:metadata.name --no-headers):output.json ./output.json \

.PHONY: clean
clean:
	echo "🧹 Cleaning up..."; \
	kubectl delete -f ./yaml/deployment.yaml -n $(NAMESPACE)
	kubectl delete -f ./yaml/postgres.yaml -n $(NAMESPACE)
