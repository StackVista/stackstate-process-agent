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
  sh "./prebuild-datadog-agent.sh -i"
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
  sh "go install github.com/mgechev/revive@latest"
  packages = `go list ./... | grep -v vendor`.split("\n")
  packages.each do |pkg|
    puts "revive -formatter stylish -config revive-recommended.toml #{pkg}"
    output = `revive -formatter stylish -config revive-recommended.toml #{pkg}`
    puts output
    if output != ""
      fail "Error during linting"
    end
  end
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
