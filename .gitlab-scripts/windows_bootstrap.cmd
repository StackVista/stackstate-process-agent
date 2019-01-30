@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
choco install -y git hg golang dep ruby msys2 mingw netcat
if exist %GOPATH%\src\github.com\StackVista\stackstate-process-agent rd /s/q %GOPATH%\src\github.com\StackVista\stackstate-process-agent
mkdir %GOPATH%\src\github.com\StackVista\stackstate-process-agent
xcopy /q/h/e/s * %GOPATH%\src\github.com\StackVista\stackstate-process-agent
cd %GOPATH%\src\github.com\StackVista\stackstate-process-agent