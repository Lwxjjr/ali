package attacker

import (
	"time"

	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// Metrics 包装 "vegeta.Metrics" 以避免对它的依赖
type Metrics struct {
	// Latencies 保存计算出的请求延迟指标
	Latencies LatencyMetrics `json:"latencies"`
	// Histogram，仅在请求时提供
	// Histogram *vegeta.Histogram `json:"buckets,omitempty"`
	// BytesIn 保存计算出的输入字节指标
	BytesIn ByteMetrics `json:"bytes_in"`
	// BytesOut 保存计算出的输出字节指标
	BytesOut ByteMetrics `json:"bytes_out"`
	// Earliest 是结果集中的最早时间戳
	Earliest time.Time `json:"earliest"`
	// Latest 是结果集中的最晚时间戳
	Latest time.Time `json:"latest"`
	// End 是结果集中的最晚时间戳加上其延迟
	End time.Time `json:"end"`
	// Duration 是攻击的持续时间
	Duration time.Duration `json:"duration"`
	// Wait 是等待目标响应的额外时间
	Wait time.Duration `json:"wait"`
	// Requests 是执行请求的总数
	Requests uint64 `json:"requests"`
	// Rate 是每秒发送请求的速率
	Rate float64 `json:"rate"`
	// Throughput 是每秒成功请求的速率
	Throughput float64 `json:"throughput"`
	// Success 是非错误响应的百分比
	Success float64 `json:"success"`
	// StatusCodes 是响应状态码的直方图
	StatusCodes map[string]int `json:"status_codes"`
	// Errors 是攻击期间目标返回的唯一错误集合
	Errors []string `json:"errors"`
}

// LatencyMetrics 保存计算出的请求延迟指标
type LatencyMetrics struct {
	// Total 是攻击中所有请求的延迟总和
	Total time.Duration `json:"total"`
	// Mean 是平均请求延迟
	Mean time.Duration `json:"mean"`
	// P50 是第50百分位请求延迟
	P50 time.Duration `json:"50th"`
	// P90 是第90百分位请求延迟
	P90 time.Duration `json:"90th"`
	// P95 是第95百分位请求延迟
	P95 time.Duration `json:"95th"`
	// P99 是第99百分位请求延迟
	P99 time.Duration `json:"99th"`
	// Max 是观察到的最大请求延迟
	Max time.Duration `json:"max"`
	// Min 是观察到的最小请求延迟
	Min time.Duration `json:"min"`
}

// ByteMetrics 保存计算出的字节流量指标
type ByteMetrics struct {
	// Total 是攻击中流过的字节总数
	Total uint64 `json:"total"`
	// Mean 是每次命中流过的平均字节数
	Mean float64 `json:"mean"`
}

func newMetrics(m *vegeta.Metrics) *Metrics {
	statusCodes := make(map[string]int, len(m.StatusCodes))
	for k, v := range m.StatusCodes {
		statusCodes[k] = v
	}

	return &Metrics{
		Latencies: LatencyMetrics{
			Total: m.Latencies.Total,
			Mean:  m.Latencies.Mean,
			P50:   m.Latencies.Quantile(0.50),
			P90:   m.Latencies.Quantile(0.90),
			P95:   m.Latencies.Quantile(0.95),
			P99:   m.Latencies.Quantile(0.99),
			Max:   m.Latencies.Max,
			Min:   m.Latencies.Min,
		},
		//Histogram:   m.Histogram,
		BytesIn: ByteMetrics{
			Total: m.BytesIn.Total,
			Mean:  m.BytesIn.Mean,
		},
		BytesOut: ByteMetrics{
			Total: m.BytesOut.Total,
			Mean:  m.BytesOut.Mean,
		},
		Earliest:    m.Earliest,
		Latest:      m.Latest,
		End:         m.End,
		Duration:    m.Duration,
		Wait:        m.Wait,
		Requests:    m.Requests,
		Rate:        m.Rate,
		Throughput:  m.Throughput,
		Success:     m.Success,
		StatusCodes: statusCodes,
		Errors:      m.Errors,
	}
}
