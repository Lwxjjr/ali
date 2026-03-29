package gui

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/mum4k/termdash"
	"github.com/mum4k/termdash/container"
	"github.com/mum4k/termdash/container/grid"
	"github.com/mum4k/termdash/linestyle"
	"github.com/mum4k/termdash/terminal/tcell"
	"github.com/mum4k/termdash/terminal/termbox"
	"github.com/mum4k/termdash/terminal/terminalapi"
	"go.uber.org/atomic"

	"github.com/nakabonne/ali/attacker"
	"github.com/nakabonne/ali/storage"
)

const (
	DefaultQueryRange     = 30 * time.Second
	DefaultRedrawInterval = 250 * time.Millisecond
	minRedrawInterval     = 100 * time.Millisecond
	rootID                = "root"
	chartID               = "chart"
)

type Options struct {
	RedrawInternal time.Duration
	QueryRange     time.Duration
}

type runner func(ctx context.Context, t terminalapi.Terminal, c *container.Container, opts ...termdash.Option) error

// Run 是 GUI 的外部入口。它会根据操作系统初始化终端后台，并启动 UI 循环。
func Run(targetURL string, storage storage.Reader, attacker attacker.Attacker, opts Options) error {
	var (
		t   terminalapi.Terminal
		err error
	)
	// 根据平台选择终端驱动：Windows 使用 tcell，其他系统使用 termbox (支持 256 色)
	if runtime.GOOS == "windows" {
		t, err = tcell.New()
	} else {
		t, err = termbox.New(termbox.ColorMode(terminalapi.ColorMode256))
	}
	if err != nil {
		return fmt.Errorf("failed to generate terminal interface: %w", err)
	}
	defer t.Close()
	return run(t, termdash.Run, targetURL, storage, attacker, opts)
}

// run 负责初始化 UI 组件、配置布局、绑定快捷键，并运行 termdash 的主循环。
func run(t terminalapi.Terminal, r runner, targetURL string, storage storage.Reader, a attacker.Attacker, opts Options) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建根容器
	c, err := container.New(t, container.ID(rootID))
	if err != nil {
		return fmt.Errorf("failed to generate container: %w", err)
	}

	// 实例化所有 UI 组件
	w, err := newWidgets(targetURL, a.Rate(), a.Duration(), a.Method())
	if err != nil {
		return fmt.Errorf("failed to generate widgets: %w", err)
	}
	// 构建网格布局
	gridOpts, err := gridLayout(w)
	if err != nil {
		return fmt.Errorf("failed to build grid layout: %w", err)
	}
	// 将布局应用到容器
	if err := c.Update(rootID, gridOpts.base...); err != nil {
		return fmt.Errorf("failed to update container: %w", err)
	}
	// 设置默认配置
	if opts.QueryRange == 0 {
		opts.QueryRange = DefaultQueryRange
	}
	if opts.RedrawInternal == 0 {
		opts.RedrawInternal = DefaultRedrawInterval
	}
	if opts.RedrawInternal < minRedrawInterval {
		return fmt.Errorf("redrawInterval must be greater than %s", minRedrawInterval)
	}

	// 初始化绘制器并启动后台异步刷新
	d := &drawer{
		queryRange:     opts.QueryRange,
		redrawInterval: opts.RedrawInternal,
		widgets:        w,
		gridOpts:       gridOpts,
		metricsCh:      make(chan *attacker.Metrics),
		chartDrawing:   atomic.NewBool(false),
		metrics:        &attacker.Metrics{},
		storage:        storage,
	}
	go d.updateMetrics(ctx)
	go d.redrawMetrics(ctx)

	// 绑定键盘快捷键
	k := keybinds(ctx, cancel, c, d, a)

	// 进入 termdash 主循环
	err = r(ctx, t, c, termdash.KeyboardSubscriber(k), termdash.RedrawInterval(opts.RedrawInternal))
	if exportErr := d.exportError(); exportErr != nil {
		return exportErr
	}
	return err
}

// newChartWithLegends 创建一个带底部图例说明的图表容器。
func newChartWithLegends(lineChart LineChart, opts []container.Option, texts ...Text) ([]container.Option, error) {
	textsInColumns := func() []grid.Element {
		els := make([]grid.Element, 0, len(texts))
		for _, text := range texts {
			els = append(els, grid.ColWidthPerc(3, grid.Widget(text)))
		}
		return els
	}

	lopts := lineChart.Options()
	el := grid.RowHeightPercWithOpts(70,
		opts,
		grid.RowHeightPerc(97, grid.ColWidthPerc(99, grid.Widget(lineChart))),
		grid.RowHeightPercWithOpts(3,
			[]container.Option{container.MarginLeftPercent(lopts.MinimumSize.X)},
			textsInColumns()...,
		),
	)

	g := grid.New()
	g.Add(el)
	return g.Build()
}

// gridOpts 存储网格中的所有选项。
// 它主要保存各部分组件的容器配置（行高、宽度、边距等），便于后续动态替换。
type gridOpts struct {
	// 基础布局选项
	base []container.Option

	// 用于在图表区域进行实时切换的容器选项
	latency     []container.Option
	percentiles []container.Option
}

// gridLayout 定义了 UI 的整体布局比例和嵌套结构。
func gridLayout(w *widgets) (*gridOpts, error) {
	// 第一行：图表展示区（占 70% 高度）
	raw1 := grid.RowHeightPercWithOpts(70,
		[]container.Option{container.ID(chartID)},
		grid.Widget(w.latencyChart, container.Border(linestyle.Light), container.BorderTitle("Latency (ms)")),
	)
	// 第二行：详细指标参数区（占 25% 高度），分为 5 列
	raw2 := grid.RowHeightPerc(25,
		grid.ColWidthPerc(20, grid.Widget(w.paramsText, container.Border(linestyle.Light), container.BorderTitle("Parameters"))),
		grid.ColWidthPerc(20, grid.Widget(w.latenciesText, container.Border(linestyle.Light), container.BorderTitle("Latencies"))),
		grid.ColWidthPerc(20, grid.Widget(w.bytesText, container.Border(linestyle.Light), container.BorderTitle("Bytes"))),
		grid.ColWidthPerc(20,
			grid.RowHeightPerc(50, grid.Widget(w.statusCodesText, container.Border(linestyle.Light), container.BorderTitle("Status Codes"))),
			grid.RowHeightPerc(50, grid.Widget(w.errorsText, container.Border(linestyle.Light), container.BorderTitle("Errors"))),
		),
		grid.ColWidthPerc(20, grid.Widget(w.othersText, container.Border(linestyle.Light), container.BorderTitle("Others"))),
	)
	// 第三行：进度条和导航说明（占 4% 高度）
	raw3 := grid.RowHeightPerc(4,
		grid.ColWidthPerc(60, grid.Widget(w.progressGauge, container.Border(linestyle.Light), container.BorderTitle("Progress"))),
		grid.ColWidthPerc(40, grid.Widget(w.navi, container.Border(linestyle.Light))),
	)

	builder := grid.New()
	builder.Add(
		raw1,
		raw2,
		raw3,
	)

	baseOpts, err := builder.Build()
	if err != nil {
		return nil, err
	}
	latencyBuilder := grid.New()
	latencyBuilder.Add(raw1)
	latencyOpts, err := latencyBuilder.Build()
	if err != nil {
		return nil, err
	}

	// 为百分位数图表构建带图例说明的布局
	percentilesOpts, err := newChartWithLegends(w.percentilesChart, []container.Option{
		container.Border(linestyle.Light),
		container.ID(chartID),
		container.BorderTitle("Percentiles (ms)"),
	}, w.p99Legend.text, w.p95Legend.text, w.p90Legend.text, w.p50Legend.text)
	if err != nil {
		return nil, err
	}

	return &gridOpts{
		latency:     latencyOpts,
		percentiles: percentilesOpts,
		base:        baseOpts,
	}, nil
}
