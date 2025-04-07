# Test server [WIP] ⚠️

## Description

This binary just spawns an HTTP server that exposes the same endpoints of the Stackstate Receiver.
The server receives all the data and just answer with `200 OK`.
You can use it to run the process agent locally.

> __WIP__: In more advanced modes this test can assert various data sent by the process agent.

## Build & Run

In this folder
Build it:

```bash
go build -o main .
```

Run it:

```bash
./main
```

## Build docker image

In this folder

```bash
docker build --tag <TAG> -f Dockerfile .
```

The docker image generated should be used by the k8s server deployment `e2e-tests/test-server.yaml`