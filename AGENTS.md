# AGENTS.md - 项目上下文文档

## 项目概述

**ali** 是一个具有实时分析功能的负载测试工具，由 Ryo Nakao 开发。该项目受到 [vegeta](https://github.com/tsenart/vegeta) 和 [jplot](https://github.com/rs/jplot) 的启发，专门为在终端上进行实时性能分析而设计。

### 核心特性

- **实时可视化**：内置基于终端的 UI，可以实时绘制性能指标图表
- **多种图表类型**：支持延迟图、百分位数图、字节数图和直方图
- **鼠标支持**：支持鼠标交互，可以拖拽选择区域进行缩放
- **进度可视化**：在长时间测试中实时显示攻击进度
- **结果导出**：可以将测试结果导出为 CSV 和 JSON 格式，用于下游处理
- **灵活的配置**：支持自定义请求头、请求体、TLS 证书、DNS 解析器等

### 技术栈

- **语言**：Go 1.24.0
- **核心依赖**：
  - `github.com/tsenart/vegeta/v12` (v12.8.4) - HTTP 负载测试引擎
  - `github.com/mum4k/termdash` (v0.16.0) - 终端 UI 渲染框架
  - `github.com/nakabonne/tstorage` (v0.3.5) - 时间序列数据存储
  - `github.com/miekg/dns` (v1.1.43) - DNS 解析
  - `github.com/golang/mock` (v1.6.0) - Mock 生成工具
  - `github.com/stretchr/testify` (v1.7.0) - 测试框架

### 项目架构

```
ali/
├── main.go                 # CLI 入口，参数解析和程序启动
├── attacker/              # 负载测试核心逻辑
│   ├── attacker.go        # 攻击器实现（基于 vegeta）
│   ├── metrics.go         # 性能指标计算
│   ├── summary.go         # 测试结果汇总
│   └── resolver.go        # 自定义 DNS 解析器
├── gui/                   # 终端 UI 实现
│   ├── gui.go             # UI 主逻辑
│   ├── drawer.go          # 图表绘制
│   ├── widgets.go         # UI 组件
│   └── keybinds.go        # 键盘绑定
├── storage/               # 时间序列数据存储
│   └── storage.go         # 基于内存的存储实现
├── export/                # 结果导出功能
│   └── export.go          # CSV 和 JSON 导出
└── docs/                  # 项目文档
```

### 核心组件说明

1. **Attacker** (`attacker/`)：基于 vegeta 库实现，负责发送 HTTP 请求并收集响应数据。支持配置请求速率、持续时间、超时、工作线程数等参数。

2. **GUI** (`gui/`)：使用 termdash 框架实现，提供实时图表展示。支持多种图表类型（延迟、百分位数、字节数等），并支持鼠标交互。

3. **Storage** (`storage/`)：基于内存的时间序列存储，用于管理测试过程中的性能数据。支持根据时间范围自动清理过期数据。

4. **Export** (`export/`)：将测试结果导出为 CSV 和 JSON 格式。CSV 包含所有数据点，JSON 包含汇总统计信息。

## 构建和运行

### 前置要求

- Go 1.16 或更高版本

### 常用命令

#### 构建项目

```bash
go build
```

构建完成后，可以直接运行：
```bash
./ali http://host.xz
```

#### 运行测试

```bash
make test
```

或直接运行：
```bash
go test -race -v -coverpkg=./... -covermode=atomic -coverprofile=coverage.txt ./...
```

#### 生成 Mock 文件

```bash
make mockgen
```

#### 发布预览

```bash
make release-dry-run
```

### 快速开始

1. **基本用法**：
```bash
ali http://host.xz
```
使用默认配置（rate=50, duration=10s）对目标进行负载测试。

2. **自定义配置**：
```bash
ali --rate=500 --duration=5m http://host.xz
```
以每秒 500 个请求的速率，持续 5 分钟进行测试。

3. **POST 请求**：
```bash
ali --body-file=/path/to/foo.json --method=POST http://host.xz
```

4. **导出结果**：
```bash
ali --export-to ./results/ http://host.xz
```

### 主要命令行选项

- `-r, --rate`：每秒请求速率（默认：50）
- `-d, --duration`：测试持续时间（默认：10s）
- `-m, --method`：HTTP 方法（默认：GET）
- `-H, --header`：请求头（可多次使用）
- `-b, --body`：请求体
- `-B, --body-file`：请求体文件
- `-t, --timeout`：每个请求的超时时间（默认：30s）
- `-w, --workers`：初始工作线程数（默认：10）
- `-c, --connections`：每个目标主机的最大空闲连接数（默认：10000）
- `--export-to`：导出结果到指定目录
- `--query-range`：图表显示的时间范围（默认：30s）
- `--redraw-interval`：屏幕重绘间隔（默认：250ms）

## 开发约定

### 代码风格

1. **格式化**：在提交代码前必须运行 `go fmt` 格式化代码
2. **Go 版本**：项目要求 Go 1.16 或更高版本
3. **测试**：所有修改都应该包含相应的测试用例
4. **Mock**：使用 `golang/mock` 生成 mock 文件，运行 `make mockgen` 更新

### 贡献流程

1. 在开始工作前，先创建一个 issue 描述要修复的 bug 或要实现的功能
2. Fork 仓库并创建新的分支进行开发
3. 编写代码并确保通过所有测试
4. 运行 `go fmt` 格式化代码
5. 提交 PR 并等待审查

### CI/CD

项目使用 GitHub Actions 进行自动化：

- **lint**：运行 golangci-lint 进行代码检查
- **test**：运行所有测试并生成覆盖率报告
- **release**：使用 GoReleaser 自动构建和发布二进制文件

### 调试

如需调试修改：
```bash
go build
./ali
```

调试日志会写入 `~/.config/ali/debug.log`（仅在使用 `--debug` 标志时）

## 测试

### 测试文件位置

- `attacker/attacker_test.go` - 攻击器测试
- `attacker/resolver_test.go` - DNS 解析器测试
- `gui/gui_test.go` - GUI 组件测试
- `gui/drawer_test.go` - 图表绘制测试
- `gui/keybinds_test.go` - 键盘绑定测试
- `export/export_test.go` - 导出功能测试
- `main_test.go` - 主程序测试

### 运行测试

```bash
# 运行所有测试（带竞态检测和覆盖率）
make test

# 运行特定包的测试
go test -v ./attacker

# 运行特定测试
go test -v -run TestName ./path/to/package
```

## 文档

### 项目文档

- `README.md` - 项目概述、安装和使用说明
- `CONTRIBUTING.md` - 贡献指南
- `docs/export.md` - 结果导出功能详细说明
- `docs/rfc/001-export.md` - 导出功能的设计文档

### API 文档

详细的 API 文档可在 [pkg.go.dev](https://pkg.go.dev/github.com/nakabonne/ali) 查看。

## 安装和发布

### 多种安装方式

项目支持多种安装方式：
- Homebrew: `brew install nakabonne/ali/ali`
- MacPorts: `sudo port install ali`
- APT: 下载 .deb 包后安装
- RPM: 下载 .rpm 包后安装
- Pacman: `pacman -S ali`
- APK: `apk add ali`
- Go: `go install github.com/nakabonne/ali@latest`
- Docker: `docker run --rm -it nakabonne/ali ali`

### 发布流程

使用 GoReleaser 自动化发布流程：
- 配置文件：`.goreleaser.yml`
- 运行 `make release-dry-run` 进行预览
- 通过 GitHub Actions 自动触发发布

## 关键注意事项

1. **存储限制**：时间序列存储会自动清理超出 `query-range * 2` 的旧数据，以控制内存使用
2. **导出目录**：使用 `--export-to` 时，如果目录已存在会报错，确保使用唯一路径
3. **无限攻击**：设置 `--duration=0` 可以进行无限期的负载测试
4. **TLS 配置**：支持自定义 TLS 证书和 CA 证书，用于测试需要特定证书的服务
5. **DNS 解析**：支持自定义 DNS 解析器，使用逗号分隔多个地址

## 已知限制

- 直方图功能当前被禁用（在代码中标记为 TODO）
- 字节数图表功能尚未实现（标记为 TBA）
- 导出到 stdout（使用 `-`）不被支持

## 许可证

项目使用开源许可证，具体请参考 LICENSE 文件。