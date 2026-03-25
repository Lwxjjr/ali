package attacker

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"

	"github.com/nakabonne/ali/export"
	"github.com/nakabonne/ali/storage"
)

/*
Package attacker 提供了 ali 的核心压测引擎实现。
该模块封装了底层的 Vegeta 库，负责：
1. 解析并管理压测配置（速率、时长、并发等）。
2. 执行实际的 HTTP 负载测试。
3. 实时采集请求结果（延迟、状态码），并将其分发给存储模块、文件导出模块以及 UI 通道。
*/
// --- 全局默认配置 ---

const (
	// DefaultRate 默认请求速率 (QPS)
	DefaultRate = 50
	// DefaultDuration 默认攻击持续时间
	DefaultDuration = 10 * time.Second
	// DefaultTimeout 默认单个请求的超时时间
	DefaultTimeout = 30 * time.Second
	// DefaultMethod 默认 HTTP 方法
	DefaultMethod = http.MethodGet
	// DefaultWorkers 默认初始并发 Worker 数
	DefaultWorkers = 10
	// DefaultMaxWorkers 默认最大并发 Worker 数 (无限制)
	DefaultMaxWorkers = math.MaxUint64
	// DefaultMaxBody 默认最大响应体读取字节数 (-1 表示不限制)
	DefaultMaxBody = int64(-1)
	// DefaultConnections 默认最大连接数
	DefaultConnections = 10000
)

// DefaultLocalAddr 默认发包的本地地址（全零地址）
var DefaultLocalAddr = net.IPAddr{IP: net.IPv4zero}

// Options 定义了压测的所有可选配置参数
type Options struct {
	// Rate 每秒请求数 (QPS)
	Rate int
	// Duration 压测持续的总时间
	Duration time.Duration
	// Timeout 单个 HTTP 请求的超时时间
	Timeout time.Duration
	// Method HTTP 请求方法 (如 GET, POST)
	Method string
	// Body 请求体内容（用于 POST/PUT）
	Body []byte
	// MaxBody 读取响应体的最大限制
	MaxBody int64
	// Header 自定义 HTTP 请求头
	Header http.Header
	// Workers 初始启动的并发协程数
	Workers uint64
	// MaxWorkers 允许启动的最大并发协程数
	MaxWorkers uint64
	// KeepAlive 是否使用持久连接
	KeepAlive bool
	// Connections 每个主机的最大闲置连接数
	Connections int
	// HTTP2 是否强制使用 HTTP/2
	HTTP2 bool
	// LocalAddr 指定发起请求的本地源 IP 地址
	LocalAddr net.IPAddr
	// Buckets 延迟统计的分布区间（用于直方图）
	Buckets []time.Duration
	// Resolvers 自定义 DNS 解析器地址列表
	Resolvers []string

	// InsecureSkipVerify 是否跳过 TLS 证书验证
	InsecureSkipVerify bool
	// CACertificatePool 自定义 CA 证书池
	CACertificatePool *x509.CertPool
	// TLSCertificates 客户端使用的 TLS 证书
	TLSCertificates []tls.Certificate

	// Attacker 底层压测引擎的接口（主要用于测试注入）
	Attacker backedAttacker

	// Exporter 负责将压测结果实时导出到文件
	Exporter *export.FileExporter
	// IDGenerator 压测任务 ID 生成函数
	IDGenerator func() string
}

// Attacker 定义了外部可调用的压测引擎接口
type Attacker interface {
	// Attack 启动压力测试。
	// metricsCh 用于接收实时的统计摘要。
	Attack(ctx context.Context, metricsCh chan *Metrics) error

	// Rate 返回当前配置的 QPS
	Rate() int
	// Duration 返回当前配置的持续时间
	Duration() time.Duration
	// Method 返回当前使用的 HTTP 方法
	Method() string
}

// --- 构造与初始化模块 ---

// NewAttacker 创建并初始化一个压测引擎实例。
// 它会验证 target URL，设置默认值，并配置 DNS/TLS。
func NewAttacker(storage storage.Writer, target string, opts *Options) (Attacker, error) {
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	if opts == nil {
		opts = &Options{}
	}
	if opts.Method == "" {
		opts.Method = DefaultMethod
	}
	if opts.Workers == 0 {
		opts.Workers = DefaultWorkers
	}
	if opts.MaxWorkers == 0 {
		opts.MaxWorkers = DefaultMaxWorkers
	}
	if opts.MaxBody == 0 {
		opts.MaxBody = DefaultMaxBody
	}
	if opts.Connections == 0 {
		opts.Connections = DefaultConnections
	}
	if opts.LocalAddr.IP == nil {
		opts.LocalAddr = DefaultLocalAddr
	}
	// 如果指定了自定义解析器，则覆盖默认 DNS 解析
	if len(opts.Resolvers) > 0 {
		net.DefaultResolver = NewResolver(opts.Resolvers)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: opts.InsecureSkipVerify,
		Certificates:       opts.TLSCertificates,
		RootCAs:            opts.CACertificatePool,
	}
	tlsConfig.BuildNameToCertificate()

	// 初始化底层的 Vegeta 引擎
	if opts.Attacker == nil {
		opts.Attacker = vegeta.NewAttacker(
			vegeta.Timeout(opts.Timeout),
			vegeta.Workers(opts.Workers),
			vegeta.MaxWorkers(opts.MaxWorkers),
			vegeta.MaxBody(opts.MaxBody),
			vegeta.Connections(opts.Connections),
			vegeta.KeepAlive(opts.KeepAlive),
			vegeta.HTTP2(opts.HTTP2),
			vegeta.LocalAddr(opts.LocalAddr),
			vegeta.TLSConfig(tlsConfig),
		)
	}
	return &attacker{
		target:             target,
		rate:               opts.Rate,
		duration:           opts.Duration,
		timeout:            opts.Timeout,
		method:             opts.Method,
		body:               opts.Body,
		maxBody:            opts.MaxBody,
		header:             opts.Header,
		workers:            opts.Workers,
		maxWorkers:         opts.MaxWorkers,
		keepAlive:          opts.KeepAlive,
		connections:        opts.Connections,
		http2:              opts.HTTP2,
		localAddr:          opts.LocalAddr,
		buckets:            opts.Buckets,
		resolvers:          opts.Resolvers,
		insecureSkipVerify: opts.InsecureSkipVerify,
		caCertificatePool:  opts.CACertificatePool,
		tlsCertificates:    opts.TLSCertificates,
		attacker:           opts.Attacker,
		storage:            storage,
		exporter:           opts.Exporter,
		idGenerator:        opts.IDGenerator,
	}, nil
}

// backedAttacker 是对底层 vegeta 攻击者的抽象接口
type backedAttacker interface {
	Attack(vegeta.Targeter, vegeta.Pacer, time.Duration, string) <-chan *vegeta.Result
	Stop()
}

// attacker 是接口 Attacker 的内部实现
type attacker struct {
	target             string
	rate               int
	duration           time.Duration
	timeout            time.Duration
	method             string
	body               []byte
	maxBody            int64
	header             http.Header
	workers            uint64
	maxWorkers         uint64
	keepAlive          bool
	connections        int
	http2              bool
	localAddr          net.IPAddr
	buckets            []time.Duration
	resolvers          []string
	insecureSkipVerify bool
	caCertificatePool  *x509.CertPool
	tlsCertificates    []tls.Certificate

	attacker backedAttacker
	storage  storage.Writer

	exporter    *export.FileExporter
	idGenerator func() string
}

// --- 核心逻辑模块 ---

// Attack 是主循环函数。它执行压测，实时收集、统计并分发结果。
func (a *attacker) Attack(ctx context.Context, metricsCh chan *Metrics) error {
	// 1. 设置发包速率和目标
	rate := vegeta.Rate{Freq: a.rate, Per: time.Second}
	targeter := vegeta.NewStaticTargeter(vegeta.Target{
		Method: a.method,
		URL:    a.target,
		Body:   a.body,
		Header: a.header,
	})

	metrics := &vegeta.Metrics{}
	if len(a.buckets) > 0 {
		metrics.Histogram = &vegeta.Histogram{Buckets: a.buckets}
	}

	// 2. 初始化 ID 生成器和导出器
	idGenerator := a.idGenerator
	if idGenerator == nil {
		idGenerator = defaultIDGenerator
	}

	var runExporter *export.Run
	if a.exporter != nil {
		var err error
		runExporter, err = a.exporter.StartRun(export.Meta{
			ID:        idGenerator(),
			TargetURL: a.target,
			Method:    a.method,
			Rate:      a.rate,
			Duration:  a.duration,
		})
		if err != nil {
			return err
		}
	}

	// 3. 开始执行攻击并处理结果流
	for res := range a.attacker.Attack(targeter, rate, a.duration, "main") {
		select {
		case <-ctx.Done():
			// 如果外部上下文取消（如 Ctrl+C），停止攻击
			a.attacker.Stop()
			if runExporter != nil {
				_ = runExporter.Abort()
			}
			return nil
		default:
			// 累加单次结果到统计器
			metrics.Add(res)
			m := newMetrics(metrics)

			// 将原始数据存入存储模块（用于 GUI 绘图）
			err := a.storage.Insert(&storage.Result{
				Code:      res.Code,
				Timestamp: res.Timestamp,
				Latency:   res.Latency,
				P50:       m.Latencies.P50,
				P90:       m.Latencies.P90,
				P95:       m.Latencies.P95,
				P99:       m.Latencies.P99,
			})
			if err != nil {
				log.Printf("failed to insert results")
				continue
			}

			// 如果开启导出，则写入文件
			if runExporter != nil {
				if err := runExporter.WriteResult(export.Result{
					Timestamp:  res.Timestamp,
					LatencyNS:  float64(res.Latency.Nanoseconds()),
					URL:        a.target,
					Method:     a.method,
					StatusCode: res.Code,
				}); err != nil {
					_ = runExporter.Abort()
					return err
				}
			}

			// 将最新的聚合统计数据发送给 UI
			metricsCh <- m
		}
	}

	// 4. 收尾工作：计算最终统计信息并关闭任务
	metrics.Close()
	finalMetrics := newMetrics(metrics)
	metricsCh <- finalMetrics
	if runExporter != nil {
		if err := runExporter.Close(newSummary(a.target, a.method, a.rate, a.duration, finalMetrics)); err != nil {
			return err
		}
	}
	return nil
}

// --- 数据获取模块 ---

func (a *attacker) Rate() int {
	return a.rate
}

func (a *attacker) Duration() time.Duration {
	return a.duration
}

func (a *attacker) Method() string {
	return a.method
}

// --- 工具函数模块 ---

// defaultIDGenerator 生成压测运行的随机 UUID。
func defaultIDGenerator() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	part1 := binary.BigEndian.Uint32(b[0:4])
	part2 := binary.BigEndian.Uint16(b[4:6])
	part3 := binary.BigEndian.Uint16(b[6:8])
	part4 := binary.BigEndian.Uint16(b[8:10])
	part5 := uint64(b[10])<<40 | uint64(b[11])<<32 | uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", part1, part2, part3, part4, part5)
}
