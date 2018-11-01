# Testing

## With separate VMs

Pre-requisites:

* Build the process-agent
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
* [Vagrant](https://www.vagrantup.com/downloads.html)

There is `Vagrantfile` setup that creates 2 Ubuntu Xenial64 vms:

```
$ vagrant up

# in one terminal:
$ vagrant ssh agent1
$ cd /opt/stackstate-process-agent
$ sudo ./process-agent -config conf-dev.yaml

# in another terminal:
$ vagrant ssh agent2
$ cd /opt/stackstate-process-agent
$ sudo ./process-agent -config conf-dev.yaml
```

For instance now we can expect a network connection between the 2 VMs:

```
# in one terminal:
$ vagrant ssh agent1
$ nc -l 61234

# in another terminal:
$ vagrant ssh agent2
$ yes | nc 192.168.56.101 61234
```
