package version

// Version 是编译期注入的 agent 版本。必须用 var（而非 const）:
// const 在编译期内联, 链接器的 -X 无法覆盖; 构建时通过
// `go build -ldflags "-X github.com/security-agent/agent/internal/version.Version=x.y.z"`
// 注入发布版本。源码默认值仅供本地开发/无注入构建兜底。
var Version = "0.2.1"
