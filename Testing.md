# Testing

Pre-requisites:

* Build the process-agent

## End-to-end (beest)

Local and VM testing below covers the agent in isolation. End-to-end verification against a
real cluster and a real SUSE Observability backend is done by
[beest](https://github.com/StackVista/beest).

The GitLab pipeline had a `beest_k8s_1_33_containerd_trigger_verification` job for this. It
was `when: manual` on every branch, so it was never automatic — someone pressed it. The
equivalent on GitHub is to dispatch the beest workflow directly:

```
gh workflow run agent-x86.yml --repo StackVista/beest \
  -f process_agent_branch_under_test=<your-branch>
```

Or from the beest repo's Actions tab, via *Run workflow*. The same
`process_agent_branch_under_test` input exists on `agent-x86.yml` (x86 EKS), `arm.yml`
(ARM EKS) and `openshift.yml` (ROSA).

You do not pass a commit or an image tag. beest resolves the branch to the latest 8-character
short SHA on it and uses that as the image tag, which is exactly what this repo's
`publish-image` job publishes.

**Images are only published from `master`.** `publish-image` and `merge-multiarch-manifest`
in `.github/workflows/ci.yml` are gated on `refs/heads/master`, so there is no image for a
feature-branch commit and beest will not find one to pull. In practice that means beest
verification currently happens *after* merge. Pre-merge verification of a feature branch is
tracked in [STAC-25521](https://stackstate.atlassian.net/browse/STAC-25521).

Note that beest runs cost real AWS infrastructure and all of its AWS workflows share a single
global concurrency lock, so runs queue rather than run in parallel.

## Local

Make sure to change in the `conf-dev.yaml` the address of the StackState backend to `localhost`.

Now run the agent locally using the dev config provided:

```
sudo ./process-agent -config conf-dev.yaml
```

Let's create a network connection :

```
# in one terminal:
$ nc -l 61234

# in another terminal:
$ yes | nc 192.168.56.101 61234
```

Check StackState UI and you should be able to find to netcat processes connected by a relation.

## With separate VMs

Pre-requisites:

* [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
* [Vagrant](https://www.vagrantup.com/downloads.html)

Make sure to change in the `conf-dev.yaml` the address of the StackState backend to `192.168.56.1`.

There is `Vagrantfile` setup that creates 2 Ubuntu Xenial64 vms and 1 Windows 2016 Server:

```
$ vagrant up

# in one terminal:
$ vagrant ssh process-agent-test
$ cd $GOPATH/src/github.com/StackVista/stackstate-process-agent
$ sudo ./process-agent -config conf-dev.yaml

# in another terminal:
$ vagrant ssh process-agent-clean
$ cd $GOPATH/src/github.com/StackVista/stackstate-process-agent
$ sudo ./process-agent -config conf-dev.yaml

# in another terminal:
$ vagrant ssh process-agent-win
> cd %GOPATH%/src/github.com/StackVista/stackstate-process-agent
> process-agent -config conf-dev.yaml
```

For instance now we can expect a network connection between the 2 VMs:

```
# in one terminal:
$ vagrant ssh process-agent-test
$ nc -l 61234

# in another terminal:
$ vagrant ssh process-agent-clean
$ yes | nc 192.168.56.101 61234
```

Check StackState UI and you should be able to find to netcat processes, running on 2 different VMs, 
connected by a relation.
