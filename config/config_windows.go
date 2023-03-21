//go:build windows
// +build windows

package config

const (
	defaultLogFilePath = "c:\\programdata\\stackstate\\logs\\process-agent.log"
)

// Process blacklist
var defaultBlacklistPatterns = []string{
	"stress",
	"cmd.exe",
	"conhost.exe",
	"DllHost.exe",
	"dwm.exe",
	"Explorer.EXE",
	"lsass.exe",
	"msdtc.exe",
	"SearchUI.exe",
	"sihost.exe",
	"smartscreen.exe",
	"svchost.exe",
	"taskhostw.exe",
	"tasklist.exe",
	"VBoxService.exe",
	"vim.exe",
	"wininit.exe",
	"winlogon.exe",
	"wlms.exe",
	"wmiprvse.exe",
	"sshd.exe",
	// Should be ignored, but gets reported with an empty command line
	//"sppsvc.exe",
	//"services.exe",
	//"csrss.exe",
	//"wininit.exe",
	//"System",
	//"smss.exe",
}
