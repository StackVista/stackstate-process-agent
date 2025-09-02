def get_tag_set(opts)
  cmd = ""
  if os != "windows"
    tag_set = 'docker kubelet kubeapiserver linux cri containerd' # Default tags for non-windows OSes (e.g. linux)
    tag_set += ' linux_bpf' if opts[:bpf]    # Add BPF if ebpf exists
    tag_set += ' netgo' if opts[:bpf] && opts[:static]
    cmd += " -tags \'#{tag_set}\'"
  end
  cmd
end

def get_ldflags(opts)
  prefix = 'main'
  commit = `git rev-parse --short HEAD`.strip
  branch = `git rev-parse --abbrev-ref HEAD`.strip
  if os == "windows"
    date = `date /T `.strip
  else
    date = `date +%FT%T%z`.strip
  end

  goversion = `go version`.strip
  agentversion = ENV["AGENT_VERSION"] || ENV["PROCESS_AGENT_VERSION"] || "0.99.0"

  vars = {}
  vars["#{prefix}.Version"] = agentversion
  if opts[:add_build_vars]
    vars["#{prefix}.BuildDate"] = date
    vars["#{prefix}.GitCommit"] = commit
    vars["#{prefix}.GitBranch"] = branch
    vars["#{prefix}.GoVersion"] = goversion
  end

  ldflags = vars.map { |name, value| "-X '#{name}=#{value}'" }

  if opts[:embed_path]
    ldflags << "-r #{opts[:embed_path]}/lib"
  end

  " -ldflags \"#{ldflags.join(' ')}\""
end

def get_env(opts)
  env = {}
  if opts[:embed_path]
    embedder_dir = opts[:embed_path]
    env['CPATH'] = "#{embedder_dir}/include"
    env['CGO_LDFLAGS_ALLOW'] = '-Wl,--wrap=.*'
    env['DYLD_LIBRARY_PATH'] = "#{embedder_dir}/lib"
    env['LD_LIBRARY_PATH'] = "#{embedder_dir}/lib"
    env['CGO_LDFLAGS'] = "-L#{embedder_dir}/lib"
    env['CGO_CFLAGS'] = " -Werror -Wno-deprecated-declarations -I#{embedder_dir}/include -I#{embedder_dir}/common"
  end
  env
end

def print_env(env)
  if env.length == 0
    puts "no additional environment variables set"
  else
    puts "additional environment variables"
    env.each do |key, value|
      puts "#{key}=#{value}"
    end
  end
end

def go_build(program, opts={})
  default_cmd = "go build -a"
  if ENV["INCREMENTAL_BUILD"] then
    default_cmd = "go build -i"
  end
  opts = {
    :cmd => default_cmd,
    :race => false,
    :add_build_vars => true,
  }.merge(opts)

  cmd = opts[:cmd]
  cmd += ' -race' if opts[:race]
  cmd += get_tag_set(opts)
  cmd += get_ldflags(opts)

  if ENV['windres'] then
    # NOTE: This value is currently hardcoded and needs to be manually incremented during release
    winversion = "6.6.0".split(".")
    resdir = "cmd/agent/windows_resources"
    # first compile the message table, as it's an input to the resource file
    msgcmd = "windmc --target pe-x86-64 -r #{resdir} #{resdir}/process-agent-msg.mc"
    puts msgcmd
    sh msgcmd

    rescmd = "windres --define MAJ_VER=#{winversion[0]} --define MIN_VER=#{winversion[1]} --define PATCH_VER=#{winversion[2]} "
    rescmd += "-i #{resdir}/process-agent.rc --target=pe-x86-64 -O coff -o cmd/agent/rsrc.syso"
    sh rescmd
  end

  env = get_env(opts)
  print_env(env)

  # Building the binary
  sh env, "#{cmd}  #{program}"

  if ENV['SIGN_WINDOWS'] then
    signcmd = "signtool sign /v /t http://timestamp.verisign.com/scripts/timestamp.dll /fd SHA256 /sm /s \"My\" /sha1 ECCDAE36FDCB654D2CBAB3E8975AA55469F96E4C process-agent.exe"
    sh signcmd
  end
end


def go_lint(path)
  out = `golint #{path}/*.go`
  errors = out.split("\n")
  puts "#{errors.length} linting issues found"
  if errors.length > 0
    puts out
    fail
  end
end

def go_vet(path, opts={})
  sh get_env(opts), "go vet #{get_tag_set(opts)} #{get_ldflags(opts)} #{path}"
end

def go_test(path, opts = {})
  cmd = "go test -count=1 #{get_tag_set(opts)} #{get_ldflags(opts)}"
  filter = ''
  if opts[:coverage_file]
    cmd += " -coverprofile=#{opts[:coverage_file]} -coverpkg=./..."
    filter = "2>&1 | grep -v 'warning: no packages being tested depend on'" # ugly hack
  end
  sh get_env(opts), "#{cmd} #{path} #{filter}"
end

# return the dependencies of all the packages who start with the root path
def go_pkg_deps(pkgs, root_path)
  deps = []
  pkgs.each do |pkg|
    deps << pkg
    `go list -f '{{ join .Deps "\\n"}}' #{pkg}`.split("\n").select do |path|
      if path.start_with? root_path
        deps << path
      end
    end
  end
  return deps.sort.uniq
end


def get_go_module_path(path)
  `go list -f '{{ .Dir }}' -m #{path}`.strip
end
