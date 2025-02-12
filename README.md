# StackState Process Agent


## Development or running from source

Pre-requisites:

* `go >= 1.10.1`
* `rake`

Check out the repo in your `$GOPATH`

```
cd $GOPATH/StackVista
git clone git@github.com:StackVista/stackstate-process-agent
cd stackstate-process-agent
```

Pull down the latest dependencies via `dep` and build the process-agent:

```
rake local_build
```

You can now run the Agent on the command-line:

```
sudo ./process-agent -config $PATH_TO_PROCESS_CONFIG_FILE
```

## Regenerating proto files

 
If you modify any of the `.proto` files you _must_ rebuild the `*.pb.go` files.

Make sure protobuf 3.6.1.3 is installed, typically has to be built from source: `https://github.com/protocolbuffers/protobuf/tree/v3.6.1.3`

Make sure you install the gogo-proto binaries from the go mod directory:

```
cd $GO_PATH/pkg/github.com/gogo/protobuf@1.3.2
make install
```

Make sure `$GO_PATH/bin` is in the `PATH`.

and then:

```
rake protobuf
```

## Working with the datadog dependency

The `prebuild-datadog-agent'sh` script is in charge of prebuilding artifacts for the main build. See --help there.

### Working against a local copy

Run `./update-datadog-dependency.sh -l <path>` to work with a local checkout of the upstream datadog agent.

### Updating the upstream reference

Run `./prebuild-datadog-agent.sh -t` to assure the tests pass (these do not run in CI due to the deep integration with the host system).
After pushing a change to `datadog-agent-upstream-for-process-agent` be sure to run `./update-datadog-dependency.sh -b <branch>` with the updated branch/tag.

### Test cycle for the datadog dependency

Part of the tests for this repo run manually, because they are very heavy/relient on setup (not super CI-friendly). Here it is described how to run those.

Use `./update-datadog-dependency.sh -l <path>` to work against a local checkout of `datadog-agent-upstream-for-process-agent`
Run `./prebuild-datadog-agent.sh -s` to get into the build shell.

Rerun `/prebuild-datadog-agent-scripts/rune-datadog-agent-test.sh rerun` to keep running the tests after a change was made
Rerun `/prebuild-datadog-agent-scripts/rune-datadog-agent-prebuild.sh rerun` to keep building the output artifacts after a change was made

## Development or Running with Vagrant

There is a Vagrantfile in the root directory, that can be used to create a vagrant vm where the StackState process agent can be run.

```
$ vagrant up process-agent-test
...
$ vagrant ssh process-agent-test
$ cd $GOPATH/src/github.com/StackVista/stackstate-process-agent
```

You can up the memory and pre-install some processes at boot of the Vagrant vm with:

```
$ MEM="2048" PROCESSES="java mysql postgresql tomcat" vagrant up process-agent-test
```

