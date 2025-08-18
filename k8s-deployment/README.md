# Deploy local agent on a k8s cluster

```bash
# 1. Create a k8s cluster (kind, minikube, k3s, ecc...)
minikube start --driver=kvm2
# 2. Deploy initial docker images (process-agent, loader-agent, test-server)
make deploy
# 3. Build locally the process-agent and the test-server (or update configs)
# 4. Push the new binaries/configs inside pods
make update
# 5. Obtain a local copy of the json output from the test server pod
make take-output
```

Everytime you do some local changes to the process-agent and test-server code, or you change a config, you should rerun `make update`

## Future improvements

- add some sort of integration tests to check the agent is working correctly in k8s
