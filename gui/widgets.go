package gui

import (
	"fmt"
	"time"

	"github.com/mum4k/termdash/cell"
	"github.com/mum4k/termdash/linestyle"
	"github.com/mum4k/termdash/widgetapi"
	"github.com/mum4k/termdash/widgets/gauge"
	"github.com/mum4k/termdash/widgets/linechart"
	"github.com/mum4k/termdash/widgets/text"
)

// LineChart 定义了折线图组件的行为接口，方便进行 mock 测试。
type LineChart interface {
	widgetapi.Widget
	Series(label string, values []float64, opts ...linechart.SeriesOption) error
}

// Text 定义了文本组件的行为接口。
type Text interface {
	widgetapi.Widget
	Write(text string, wOpts ...text.WriteOption) error
}

// Gauge 定义了仪表盘（进度条）组件的行为接口。
type Gauge interface {
	widgetapi.Widget
	Percent(p int, opts ...gauge.Option) error
}

// chartLegend 将文本组件和单元格样式组合，用于图表图例展示。
type chartLegend struct {
	text     Text
	cellOpts []cell.Option
}

// widgets 包含了 UI 界面中用到的所有组件实例。
type widgets struct {
	// latencyChart 展示实时延迟的折线图
	latencyChart LineChart

	// 各种信息展示文本块
	paramsText      Text // 攻击参数（目标、速率等）
	latenciesText   Text // 详细延迟统计（Mean, P50, P90...）
	bytesText       Text // 流量统计
	statusCodesText Text // HTTP 状态码分布
	errorsText      Text // 错误信息列表
	othersText      Text // 其他指标（吞吐量、成功率等）

	// percentilesChart 展示百分位数分布的折线图
	percentilesChart LineChart
	p99Legend        chartLegend
	p95Legend        chartLegend
	p90Legend        chartLegend
	p50Legend        chartLegend

	// progressGauge 显示攻击进度的进度条
	progressGauge Gauge
	// navi 显示操作快捷键提示
	navi          Text
}

// newWidgets 构造并初始化所有 UI 组件。
// targetURL, rate, duration, method 用于填充初始的参数展示区。
func newWidgets(targetURL string, rate int, duration time.Duration, method string) (*widgets, error) {
	latencyChart, err := newLineChart()
	if err != nil {
		return nil, err
	}

	latenciesText, err := newText("")
	if err != nil {
		return nil, err
	}
	bytesText, err := newText("")
	if err != nil {
		return nil, err
	}
	statusCodesText, err := newText("")
	if err != nil {
		return nil, err
	}
	errorsText, err := newText("")
	if err != nil {
		return nil, err
	}
	othersText, err := newText("")
	if err != nil {
		return nil, err
	}

	// 初始化图例及其颜色
	p99Color := cell.FgColor(cell.ColorNumber(87))
	p99Text, err := newText("p99", text.WriteCellOpts(p99Color))
	if err != nil {
		return nil, err
	}
	p95Color := cell.FgColor(cell.ColorGreen)
	p95Text, err := newText("p95", text.WriteCellOpts(p95Color))
	if err != nil {
		return nil, err
	}
	p90Color := cell.FgColor(cell.ColorYellow)
	p90Text, err := newText("p90", text.WriteCellOpts(p90Color))
	if err != nil {
		return nil, err
	}
	p50Color := cell.FgColor(cell.ColorMagenta)
	p50Text, err := newText("p50", text.WriteCellOpts(p50Color))
	if err != nil {
		return nil, err
	}
	percentilesChart, err := newLineChart()
	if err != nil {
		return nil, err
	}

	paramsText, err := newText(makeParamsText(targetURL, rate, duration, method))
	if err != nil {
		return nil, err
	}

	navi, err := newText("q: quit, Enter: attack, l: next chart, h: prev chart")
	if err != nil {
		return nil, err
	}
	progressGauge, err := newGauge()
	if err != nil {
		return nil, err
	}
	return &widgets{
		latencyChart:     latencyChart,
		paramsText:       paramsText,
		latenciesText:    latenciesText,
		bytesText:        bytesText,
		statusCodesText:  statusCodesText,
		errorsText:       errorsText,
		othersText:       othersText,
		progressGauge:    progressGauge,
		percentilesChart: percentilesChart,
		p99Legend:        chartLegend{p99Text, []cell.Option{p99Color}},
		p95Legend:        chartLegend{p95Text, []cell.Option{p95Color}},
		p90Legend:        chartLegend{p90Text, []cell.Option{p90Color}},
		p50Legend:        chartLegend{p50Text, []cell.Option{p50Color}},
		navi:             navi,
	}, nil
}

// newLineChart 创建并配置折线图的轴颜色等基本样式。
func newLineChart() (LineChart, error) {
	return linechart.New(
		linechart.AxesCellOpts(cell.FgColor(cell.ColorRed)),
		linechart.YLabelCellOpts(cell.FgColor(cell.ColorGreen)),
		linechart.XLabelCellOpts(cell.FgColor(cell.ColorGreen)),
	)
}

// newText 创建并配置文本组件，支持自动换行和滚动。
func newText(s string, opts ...text.WriteOption) (Text, error) {
	t, err := text.New(text.RollContent(), text.WrapAtWords())
	if err != nil {
		return nil, err
	}
	if s != "" {
		if err := t.Write(s, opts...); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// newGauge 创建并配置进度条组件。
func newGauge() (Gauge, error) {
	return gauge.New(
		gauge.Border(linestyle.None),
	)
}

// makeParamsText 格式化攻击参数文本。
func makeParamsText(targetURL string, rate int, duration time.Duration, method string) string {
	return fmt.Sprintf(`Target: %s
Rate: %d
Duration: %v
Method: %s
`, targetURL, rate, duration, method)
}
