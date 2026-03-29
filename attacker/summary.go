package attacker

import (
	"time"

	"github.com/nakabonne/ali/export"
)

// newSummary 将测试元数据和收集到的指标（Metrics）转换为可导出的汇总报告（Summary）。
// 它充当了指标采样数据与最终输出格式之间的适配器。
func newSummary(targetURL, method string, rate int, duration time.Duration, metrics *Metrics) export.Summary {
	return export.Summary{
		// 测试目标的基本信息
		Target: export.TargetSummary{
			URL:    targetURL,
			Method: method,
		},
		// 测试执行时的配置参数
		Parameters: export.ParametersSummary{
			Rate:            rate,
			DurationSeconds: duration.Seconds(),
		},
		// 时间线：记录测试中最早和最晚请求的时间戳
		Timing: export.TimingSummary{
			Earliest: metrics.Earliest,
			Latest:   metrics.Latest,
		},
		// 请求统计：包含请求总量和成功率（0.0-1.0）
		Requests: export.RequestsSummary{
			Count:        metrics.Requests,
			SuccessRatio: metrics.Success,
		},
		// 吞吐量（每秒成功的请求数）
		Throughput: metrics.Throughput,
		// 延迟统计：将所有的 time.Duration 转换为毫秒（ms）浮点数
		LatencyMS: export.LatencySummary{
			Total: durationToMillis(metrics.Latencies.Total),
			Mean:  durationToMillis(metrics.Latencies.Mean),
			P50:   durationToMillis(metrics.Latencies.P50), // 中位数
			P90:   durationToMillis(metrics.Latencies.P90),
			P95:   durationToMillis(metrics.Latencies.P95),
			P99:   durationToMillis(metrics.Latencies.P99),
			Max:   durationToMillis(metrics.Latencies.Max),
			Min:   durationToMillis(metrics.Latencies.Min),
		},
		// 流量统计：包含流入（响应体）和流出（请求体）的字节数汇总及平均值
		Bytes: export.BytesSummary{
			In: export.BytesFlowSummary{
				Total: metrics.BytesIn.Total,
				Mean:  metrics.BytesIn.Mean,
			},
			Out: export.BytesFlowSummary{
				Total: metrics.BytesOut.Total,
				Mean:  metrics.BytesOut.Mean,
			},
		},
		// 状态码分布：直接映射指标中收集的 HTTP 状态码计数
		StatusCodes: export.StatusCodesSummary(metrics.StatusCodes),
	}
}

// durationToMillis 将 Go 原生的 time.Duration 转换为毫秒单位的 float64 值。
func durationToMillis(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}
