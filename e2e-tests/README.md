# e2e tests [WIP] ⚠️

Right now everything is manual but the idea is to automate the process with Ansible or something like that.
The idea is something similar to beest tests but without the platform deployment. We just have a fake receiver that assert the messages received.

## Run them manually

Right now we support only a simple postgres example (client-server)

```bash
# Install a local k3s cluster (one single node is enough)
k3sup install --local
# Deploy the postgres application in the default namespace
kubectl apply -f ./postgres.yaml
# Create the monitoring namespace
kubectl create namespace monitoring
# Deploy the test server
kubectl apply -f ./test-server.yaml -n monitoring
# Deploy the process agent
helm install \
  suse-obserability-agent \
  <repo> \
  --set-string 'stackstate.apiKey'='null' \
  --set-string 'stackstate.cluster.name'='random' \
  --set-string 'stackstate.url'='http://test-server-service:7077/stsAgent' \
  --set-string 'logsAgent.enabled'='false' \
  --namespace monitoring \
  --create-namespace \
  --install --devel \
  --set-string 'nodeAgent.containers.processAgent.image.pullPolicy'='Always' \
  --set-string 'nodeAgent.containers.processAgent.image.tag'='...' \
  --set-string 'nodeAgent.containers.processAgent.image.registry'='...' \
  --set-string 'nodeAgent.containers.processAgent.image.repository'='...'
```

Uninstall

```bash
helm uninstall suse-obserability-agent --namespace monitoring
kubectl delete job test-server -n monitoring
kubectl delete service test-server-service -n monitoring
kubectl delete namespace monitoring
kubectl delete deployment postgres-server
kubectl delete deployment postgres-client
k3s-uninstall.sh
```

With the current configuration you should find the `output.json` file under `/tmp/output.json` in your file system.
