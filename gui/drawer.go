package gui

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/mum4k/termdash/cell"
	"github.com/mum4k/termdash/widgets/linechart"
	"github.com/mum4k/termdash/widgets/text"
	"go.uber.org/atomic"

	"github.com/nakabonne/ali/attacker"
	"github.com/nakabonne/ali/storage"
)

// drawer 负责定期从存储中查询数据点，并将它们同步到 termdash 组件中。
type drawer struct {
	// queryRange 指定在 UI 图表上显示的历史数据时间范围
	queryRange     time.Duration
	// redrawInterval 指定屏幕重绘的时间间隔
	redrawInterval time.Duration
	// widgets 持有所有的 UI 组件实例
	widgets        *widgets
	// gridOpts 保存网格布局的配置
	gridOpts       *gridOpts

	// metricsCh 用于接收从攻击器传来的实时指标数据
	metricsCh chan *attacker.Metrics

	// chartDrawing 使用原子布尔值防止在单次攻击中重复启动绘制协程
	chartDrawing *atomic.Bool

	mu      sync.RWMutex
	// metrics 缓存当前的最新指标，用于文本展示
	metrics *attacker.Metrics
	// storage 提供对时间序列数据的读取能力
	storage storage.Reader

	errMu     sync.Mutex
	exportErr error
}

// redrawCharts 以 redrawInterval 为间隔，从存储中拉取数据并更新折线图（延迟图和百分位数图）。
func (d *drawer) redrawCharts(ctx context.Context) {
	ticker := time.NewTicker(d.redrawInterval)
	defer ticker.Stop()

	d.chartDrawing.Store(true)
L:
	for {
		select {
		case <-ctx.Done():
			break L
		case <-ticker.C:
			end := time.Now()
			start := end.Add(-d.queryRange)

			// 更新实时延迟图表
			latencies, err := d.storage.Select(storage.LatencyMetricName, start, end)
			if err != nil {
				log.Printf("failed to select latency data points: %v\n", err)
			}
			d.widgets.latencyChart.Series("latency", latencies,
				linechart.SeriesCellOpts(cell.FgColor(cell.ColorNumber(87))),
				linechart.SeriesXLabels(map[int]string{
					0: "req",
				}),
			)

			// 更新百分位数图表（P50, P90, P95, P99）
			p50, err := d.storage.Select(storage.P50MetricName, start, end)
			if err != nil {
				log.Printf("failed to select p50 data points: %v\n", err)
			}
			d.widgets.percentilesChart.Series("p50", p50,
				linechart.SeriesCellOpts(d.widgets.p50Legend.cellOpts...),
			)

			p90, err := d.storage.Select(storage.P90MetricName, start, end)
			if err != nil {
				log.Printf("failed to select p90 data points: %v\n", err)
			}
			d.widgets.percentilesChart.Series("p90", p90,
				linechart.SeriesCellOpts(d.widgets.p90Legend.cellOpts...),
			)

			p95, err := d.storage.Select(storage.P95MetricName, start, end)
			if err != nil {
				log.Printf("failed to select p95 data points: %v\n", err)
			}
			d.widgets.percentilesChart.Series("p95", p95,
				linechart.SeriesCellOpts(d.widgets.p95Legend.cellOpts...),
			)

			p99, err := d.storage.Select(storage.P99MetricName, start, end)
			if err != nil {
				log.Printf("failed to select p99 data points: %v\n", err)
			}
			d.widgets.percentilesChart.Series("p99", p99,
				linechart.SeriesCellOpts(d.widgets.p99Legend.cellOpts...),
			)
		}
	}
	d.chartDrawing.Store(false)
}

// redrawGauge 负责更新攻击进度的仪表盘。
func (d *drawer) redrawGauge(ctx context.Context, duration time.Duration) {
	ticker := time.NewTicker(d.redrawInterval)
	defer ticker.Stop()

	totalTime := float64(duration)

	d.widgets.progressGauge.Percent(0)
	for start := time.Now(); ; {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			passed := float64(time.Since(start))
			percent := int(passed / totalTime * 100)
			// 由于 time.Duration 单位是纳秒，在慢速机器上微小的时间差可能导致百分比超过 100
			if percent > 100 {
				continue
			}
			d.widgets.progressGauge.Percent(percent)
		}
	}
}

const (
	latenciesTextFormat = `Total: %v
Mean: %v
P50: %v
P90: %v
P95: %v
P99: %v
Max: %v
Min: %v`

	bytesTextFormat = `In:
  Total: %v
  Mean: %v
Out:
  Total: %v
  Mean: %v`

	othersTextFormat = `Duration: %v
Wait: %v
Requests: %d
Rate: %f
Throughput: %f
Success: %f
Earliest: %v
Latest: %v
End: %v`
)

// redrawMetrics 以 redrawInterval 指定的间隔，将自身保存的指标写入组件
func (d *drawer) redrawMetrics(ctx context.Context) {
	ticker := time.NewTicker(d.redrawInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.mu.RLock()
			m := *d.metrics
			d.mu.RUnlock()

			d.widgets.latenciesText.Write(
				fmt.Sprintf(latenciesTextFormat,
					m.Latencies.Total,
					m.Latencies.Mean,
					m.Latencies.P50,
					m.Latencies.P90,
					m.Latencies.P95,
					m.Latencies.P99,
					m.Latencies.Max,
					m.Latencies.Min,
				), text.WriteReplace())

			d.widgets.bytesText.Write(
				fmt.Sprintf(bytesTextFormat,
					m.BytesIn.Total,
					m.BytesIn.Mean,
					m.BytesOut.Total,
					m.BytesOut.Mean,
				), text.WriteReplace())

			d.widgets.othersText.Write(fmt.Sprintf(othersTextFormat,
				m.Duration,
				m.Wait,
				m.Requests,
				m.Rate,
				m.Throughput,
				m.Success,
				m.Earliest.Format(time.RFC3339),
				m.Latest.Format(time.RFC3339),
				m.End.Format(time.RFC3339),
			), text.WriteReplace())

			// To guarantee that status codes are in order
			// taking the slice of keys and sorting them.
			codesText := ""
			var keys []string
			for k := range m.StatusCodes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				codesText += fmt.Sprintf(`%q: %d
`, k, m.StatusCodes[k])
			}
			d.widgets.statusCodesText.Write(codesText, text.WriteReplace())

			errorsText := ""
			for _, e := range m.Errors {
				errorsText += fmt.Sprintf(`- %s
`, e)
			}
			d.widgets.errorsText.Write(errorsText, text.WriteReplace())
		}
	}
}

func (d *drawer) updateMetrics(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case metrics := <-d.metricsCh:
			if metrics == nil {
				continue
			}
			d.mu.Lock()
			d.metrics = metrics
			d.mu.Unlock()
		}
	}
}

func (d *drawer) setExportErr(err error) {
	if err == nil {
		return
	}
	d.errMu.Lock()
	if d.exportErr == nil {
		d.exportErr = err
	}
	d.errMu.Unlock()
}

func (d *drawer) exportError() error {
	d.errMu.Lock()
	defer d.errMu.Unlock()
	return d.exportErr
}
