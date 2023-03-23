require "./gorake.rb"

def os
    case RUBY_PLATFORM
    when /linux/
      "linux"
    when /darwin/
      "darwin"
    when /x64-mingw32/
      "windows"
    else
      fail 'Unsupported OS'
    end
  end

desc "Setup dependencies"
task :deps do
  system("go mod download")
end

task :default => [:ci]

desc "Build Datadog Process agent"
task :build do
  case os
  when "windows"
    bin = "process-agent.exe"
  else
    bin = "process-agent"
  end
  sh "./prebuild-datadog-agent.sh -i"
  go_build("github.com/StackVista/stackstate-process-agent/cmd/agent", {
    :cmd => "go build -o #{bin}",
    :race => ENV['GO_RACE'] == 'true',
    :add_build_vars => ENV['PROCESS_AGENT_ADD_BUILD_VARS'] != 'false',
    :embed_path => ENV['STACKSTATE_EMBEDDED_PATH'],
    :bpf => true
  })
end


desc "Run goderive to generate necessary go code"
task :derive do
  sh "go run github.com/awalterschulze/goderive@886b66b111a4 ./..."
end

desc "Run prebuild steps"
task :prebuild do
  sh "./prebuild-datadog-agent.sh -g"
end

desc "Run goderive to generate necessary go code (Windows)"
task :derive_win do
  system("go install github.com/awalterschulze/goderive@886b66b111a4")
  system("go generate ./...")
end

desc "Install Datadog Process agent"
task :install do
  case os
  when "windows"
    bin = "process-agent.exe"
  else
    bin = "process-agent"
  end    
  go_build("github.com/StackVista/stackstate-process-agent/agent", :cmd=> "go build -i -o $GOPATH/bin/#{bin}")
end

desc "Test Datadog Process agent"
task :test do
  go_test("$(go list ./...)", {
   :bpf => true,
   :embed_path => ENV['STACKSTATE_EMBEDDED_PATH'],
  })
end

desc "Test Datadog Process agent -- cmd"
task :cmdtest do
  cmd = "for /f %f in ('go list ./... ^| find /V \"vendor\"') do go test %f"
  sh cmd
end

task :vet do
  go_vet("$(go list ./...)", {
    :bpf => true,
    :embed_path => ENV['STACKSTATE_EMBEDDED_PATH'],
  })
end

task :fmt do
  packages = `go list ./... | grep -v vendor`.split("\n")
  packages.each do |pkg|
    go_fmt(pkg)
  end
end

task :lint do
  error = false
  packages = `go list ./... | grep -v vendor`.split("\n")
  packages.each do |pkg|
    puts "golint #{pkg}"
    output = `golint #{pkg}`.split("\n")
    output = output.reject do |line|
      filename = line.split(':')[0]
      filename.end_with? '.pb.go'
    end
    if !output.empty?
      puts output
      error = true
    end
  end
  fail "We have some linting errors" if error
end

desc "Compile the protobuf files for the Process Agent"
task :protobuf do
  protocv = `bash -c "protoc --version"`.strip
  if protocv != 'libprotoc 3.6.1'
    fail "Requires protoc version 3.6.1"
  end

  gogo_path = get_go_module_path("github.com/gogo/protobuf")
  sketched_path = get_go_module_path("github.com/DataDog/sketches-go")

  sh "protoc proto/agent_payload.proto --proto_path=#{gogo_path} -I proto --gogofaster_out model/"
  sh "protoc proto/agent.proto --proto_path=#{gogo_path} --proto_path=#{sketched_path} -I proto --gogofaster_out model/"
end

desc "Process Agent CI script (fmt, vet, etc)"
task :ci => [:deps, :fmt, :vet, :test, :lint, :build]

desc "Process Agent local build"
task :local_build => [:deps, :prebuild, :build]

task :err do
  system("go install github.com/kisielk/errcheck")
  sh "errcheck github.com/StackVista/stackstate-process-agent"
end

task 'windows-versioned-artifact' do
  process_agent_version = `bash -c "packaging/version.sh"`.strip!
  system("cp process-agent.exe stackstate-process-agent-%s.exe" % process_agent_version)
end

task 'windows-tag-or-commit-artifact' do
  process_agent_version = `bash -c "packaging/commit-or-tag.sh"`.strip!
  sh "echo %s" % process_agent_version
  system("cp process-agent.exe stackstate-process-agent-%s.exe" % process_agent_version)
end


# ========= embedded_path: /opt/stackstate-agent/embedded
# ========= rtloader_root: None
# ========= rtloader_lib: ['/opt/stackstate-agent/embedded/lib']
# {
# go build -mod=mod  -a -tags "
#  kubelet secrets orchestrator systemd containerd jetson jmx npm etcd
# cri linux_bpf apm python docker zlib gce zk consul process netcgo ec2 kubeapiserver clusterchecks"
# -o ./bin/system-probe/system-probe -gcflags=""
# -ldflags="
#               -X github.com/StackVista/stackstate-agent/pkg/version.Commit=ea4aa0a76
#               -X github.com/StackVista/stackstate-agent/pkg/version.AgentVersion=2.19.1+git.7.ea4aa0a
#               -X github.com/StackVista/stackstate-agent/pkg/serializer.AgentPayloadVersion=v5.0.4
#               -X github.com/StackVista/stackstate-agent/pkg/config.ForceDefaultPython=true
#               -X github.com/StackVista/stackstate-agent/pkg/config.DefaultPython=3
#               -r /opt/stackstate-agent/embedded/lib "
#  github.com/StackVista/stackstate-agent/cmd/system-probe

# cmdgo build -o process-agent -tags 'docker kubelet kubeapiserver linux cri containerd linux_bpf'
# -ldflags "
#             -X 'main.GitCommit=b49885de'
#             -X 'main.Version=0.99.0'
#             -X 'main.BuildDate=2022-12-06T19:41:18+0000'
#             -X 'main.GitBranch=upstream-connections'
#             -X 'main.GoVersion=go version go1.17.13 linux/amd64'"
# github.com/StackVista/stackstate-process-agent/cmd/agent