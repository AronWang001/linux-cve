// Package buildinfo 保存构建期注入的版本信息。
//
// 通过 -ldflags "-X .../buildinfo.Version=..." 注入，不在代码里手工改版本号。
package buildinfo

import "runtime"

var (
	// Version 是语义化版本号，开发期为 2.0.0-dev。
	Version = "2.0.0-dev"
	// Commit 是构建时的提交短哈希；未注入时显示 unknown，
	// 不得回退为任何基线/历史提交号冒充当前构建。
	Commit = "unknown"
	// BuildDate 是构建时间，RFC3339；未注入时显示 unknown。
	BuildDate = "unknown"
)

// Info 是可序列化的版本信息。
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get 返回当前构建信息。
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// String 返回单行可读版本串。
func String() string {
	i := Get()
	return "linux-cve " + i.Version +
		" (commit " + i.Commit +
		", built " + i.BuildDate +
		", " + i.GoVersion +
		", " + i.Platform + ")"
}
