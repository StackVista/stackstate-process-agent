Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco install -y git hg golang dep ruby mingw netcat

setx GOPATH "C:\opt\stackstate-go"
setx GO_PROCESS_AGENT "C:\opt\stackstate-go\src\github.com\StackVista\stackstate-process-agent"
setx path "%path%;%GOPATH%\bin"
setx DEPNOLOCK 1

refreshenv

if (Get-Command rake -errorAction SilentlyContinue)
{
    rake --version
} else {
    C:\tools\ruby26\bin\gem install rake
}