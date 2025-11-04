package version

import (
	"fmt"
	"runtime"
)

var (
	GitVersion    = "dev"
	BuildMetadata = ""
	GitCommit     = ""
	GitTreeState  = ""
)

func GetVersion() string {
	var version string
	if BuildMetadata != "" {
		version = fmt.Sprintf("%s+%s", GitVersion, BuildMetadata)
	} else {
		version = GitVersion
	}
	return version
}

func GetVersionInfo() map[string]string {
	return map[string]string{
		"version":      GetVersion(),
		"gitCommit":    GitCommit,
		"gitTreeState": GitTreeState,
		"goVersion":    runtime.Version(),
		"platform":     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}
