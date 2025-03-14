# StackState Process Agent

## Requirements

* `go >= 1.10.1`
* `rake`

## Build the process agent

If you want to use a custom version of `datadog-agent-upstream-for-process-agent` use the following script before invoking the build command.

```bash
./update-datadog-dependency.sh -l <path-to-local-datadog-repo>
./update-datadog-dependency.sh -b <branch-name>
```

```bash
rake local_build
# The dockerfile and the config `conf-dev.yaml` expect the .o file under a specific folder. This command just moves these files.
./prebuild-datadog-agent.sh --install-ebpf
# DataDog checks that ebpf .o files are owned by root,
sudo chown root:root -R ./ebpf-object-files/x86_64

```

## Run the agent locally

You can now run the Agent on the command-line:

```bash
sudo ./process-agent -config ./conf-dev.yaml
```

To run without errors the process-agent needs the `test-server`. Start the `test-server` before the process-agent.

## Build the docker image

You first need to build the process agent locally as described above.
Once you have the binary and the ebpf artifacts locally, you can simply use the dockerfile

```bash
docker build --tag <tag> -f Dockerfile .
```

## Regenerating proto files

If you modify any of the `.proto` files you _must_ rebuild the `*.pb.go` files.

Make sure protobuf 3.6.1.3 is installed, typically has to be built from source: `https://github.com/protocolbuffers/protobuf/tree/v3.6.1.3`

Make sure you install the gogo-proto binaries from the go mod directory:

```bash
cd $GO_PATH/pkg/github.com/gogo/protobuf@1.3.2
make install
```

Make sure `$GO_PATH/bin` is in the `PATH`.

and then:

```bash
rake protobuf
```

## [NO MORE MANTAINED] Development or Running with Vagrant

There is a Vagrantfile in the root directory, that can be used to create a vagrant vm where the StackState process agent can be run.

```bash
$ vagrant up process-agent-test
#...
$ vagrant ssh process-agent-test
$ cd $GOPATH/src/github.com/StackVista/stackstate-process-agent
```

You can up the memory and pre-install some processes at boot of the Vagrant vm with:

```bash
MEM="2048" PROCESSES="java mysql postgresql tomcat" vagrant up process-agent-test
```
