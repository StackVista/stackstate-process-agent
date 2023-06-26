# StackState Process Agent

[![CircleCI](https://circleci.com/gh/StackVista/stackstate-process-agent.svg?style=svg)](https://circleci.com/gh/StackVista/stackstate-process-agent)

## Installation

See the [Live Processes docs](https://docs.datadoghq.com/graphing/infrastructure/process/#installation) for installation instructions.

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

First make sure you install the gogo-proto binaries from the `./vendor`:

```
cd vendor/github.com/gogo/protobuf
make install
```

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

Use `./update-datadog-dependency.sh -l <path>` to work against a local checkout of `datadog-agent-upstream-for-process-agent`
Run `./prebuild-datadog-agent.sh -s` to get into the build shell.

Rerun `/scripts/rune-datadog-agent-test.sh rerun` to keep running the tests after a change was made
Rerun `/scripts/rune-datadog-agent-prebuild.sh rerun` to keep building the output artifacts after a change was made

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

## Testing

Instructions related to manual testing can be found in [Testing.md](Testing.md)

## Contributing

In order for your contributions you will be required to sign a CLA. When a PR is opened a bot will prompt you to sign the CLA. Once signed you will be set for all contributions going forward.

