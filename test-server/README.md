# Test server

## Description

This binary just spawns an HTTP server that exposes the same endpoints of the Stackstate Receiver.
The server receives all the data and just answer with `200 OK`.
You can use it to run the process agent locally.

## Build & Run

In the `test-server` folder
Build it:

```bash
go build .
```

Run it:

```bash
./test-server
```
