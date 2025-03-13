# Run the process-agent locally against the test server

## Build the test server

In the test-server folder
Build it:

```bash
go build .
```

Run it:

```bash
./test-server
```

## process agent

In the project root folder
Build it:

```bash
rake local_build
./prebuild-datadog-agent.sh --install-ebpf
sudo chown root:root -R ./ebpf-object-files/x86_64
```

Run it:

```bash
sudo ./process-agent -config conf-dev.yaml
```
