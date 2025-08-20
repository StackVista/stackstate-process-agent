# k8s deployment

## Goals of this folder

1. Quickly iterate on the development of the process agent. No need of rebuilding docker images for every change, it is enough to restart existing pods with the new agent binaries.
2. Run integration tests against the process agent. At the moment we have integration tests only for the agent exposing OTEL metrics.

## 1. Deploy local agent binary into a k8s cluster

These are the steps required to have a process agent up and running in a local Kubernetes cluster.

```bash
# 1. Create a k8s cluster (kind, minikube, k3s, ecc...)
minikube start --driver=kvm2

# 2. Deploy initial docker images (process-agent, loader-agent, test-server, OTEL collector, prometheus)
make deploy

# 3. Build locally the process-agent and the test-server (or update configs)
rake local_build
# see how to build the process agent and ebpf artifacts in the project README.md

# 4. Push the new binaries/configs inside pods
make update
```

Everytime you do some local changes to the process-agent and test-server code, or you change a config, you should rerun `make update`

### Legacy Metrics

If you want to obtain a local copy of the json output from the test server pod you can run:

```bash
make take-output
```

### OTEL Metrics

You can inspect OTEL metrics using Prometheus. The Prometheus UI can be accessed by through the NodePort service:

```bash
PROMETHEUS_PORT=$(kubectl get services -A -o json | jq -r '.items[] | select(.metadata.name == "prometheus-service") | .spec.ports[] | select(.name == "web") | .nodePort')
PROMETHEUS_ADDR=$(kubectl get nodes -A -o json | jq -r '.items[] | select(.metadata.name == "minikube") | .status.addresses[] | select(.type == "InternalIP") | .address')
echo "Prometheus is available at: http://${PROMETHEUS_ADDR}:${PROMETHEUS_PORT}"
```

## 2. Test OTEL metrics

In order to run e2e tests you need the the cluster up and running with the agent already deployed

```bash
make e2e-tests
```
