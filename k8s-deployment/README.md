# k8s deployment

## Goals of this folder

1. Quickly iterate on the development of the process agent deploying it in a local k8s cluster.
2. Run integration tests against the process agent. At the moment we have integration tests only for OTEL metrics.

## 1. Deploy local agent binary into a k8s cluster

These are the steps required to have a process agent up and running in a local Kubernetes cluster.

```bash
# 1. Create a minikube k8s cluster
make create-cluster

# 2. Deploy the setup
# Here we have 2 options:
# 1. Option "local": 
# - the agent will send legacy metrics to a local test server.
# - the agent will send OTEL metrics to a local OTEL collector and then prometheus will scrape the OTEL collector
# In this case, environment variables are not strictly necessary since they have default values in the Makefile, you can define them just to be sure you have a clean setup
export SETUP_AGENT_HELM_CHART_DIR=<path_to_your_local_agent_helm_chart>
export SETUP_TYPE=local
export SETUP_RECEIVER_ENDPOINT=http://test-server-service:7077/stsAgent
make deploy

# 2. Option "remote": 
# - the agent will send legacy metrics to the platform receiver.
# - the agent will send OTEL metrics to a local OTEL collector and then this collector will forward them to the platform OTEL endpoint.
export SETUP_AGENT_HELM_CHART_DIR=<path_to_your_local_agent_helm_chart>
export SETUP_TYPE=remote
export SETUP_API_KEY=<your_stackstate_platform_api_key>
export SETUP_CLUSTER_NAME=<your_cluster_name>
export SETUP_RECEIVER_ENDPOINT=<your_stackstate_platform_endpoint>
make deploy

# 3. If you need to push new changes to the agent binary, you can run redeploy-agent
make redeploy-agent

# 4. delete the cluster
make delete-cluster
```

### Legacy Metrics

If you want to obtain a local copy of the json output from the test server pod you can run:

```bash
make take-output
```

### OTEL Metrics

You can inspect OTEL metrics using Prometheus. The Prometheus UI can be accessed by through the NodePort service:

```bash
PROMETHEUS_PORT=$(kubectl get --namespace open-telemetry -o jsonpath="{.spec.ports[0].nodePort}" services prometheus-server)
PROMETHEUS_ADDR=$(kubectl get nodes --namespace open-telemetry -o jsonpath="{.items[0].status.addresses[0].address}")
echo http://$PROMETHEUS_ADDR:$PROMETHEUS_PORT
```

## 2. Test OTEL metrics

In order to run e2e tests you need the the cluster up and running with the agent already deployed

```bash
kubectl apply -f ./yaml/postgres.yaml
make e2e-tests
```
