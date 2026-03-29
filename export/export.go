package export

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

const (
	resultsFilename = "results.csv"
)

var resultsHeader = []string{"id", "timestamp", "latency_ns", "url", "method", "status_code"}

// Meta 包含导出运行的元数据。
type Meta struct {
	ID        string
	TargetURL string
	Method    string
	Rate      int
	Duration  time.Duration
}

// Result 表示要导出的单个请求结果。
type Result struct {
	Timestamp  time.Time
	LatencyNS  float64
	URL        string
	Method     string
	StatusCode uint16
}

// Summary 包含压力测试运行的汇总统计信息。
type Summary struct {
	Target      TargetSummary      `json:"target"`
	Parameters  ParametersSummary  `json:"parameters"`
	Timing      TimingSummary      `json:"timing"`
	Requests    RequestsSummary    `json:"requests"`
	Throughput  float64            `json:"throughput"`
	LatencyMS   LatencySummary     `json:"latency_ms"`
	Bytes       BytesSummary       `json:"bytes"`
	StatusCodes StatusCodesSummary `json:"status_codes"`
}

// TargetSummary 包含目标信息。
type TargetSummary struct {
	URL    string `json:"url"`
	Method string `json:"method"`
}

// ParametersSummary 包含用于压力测试的参数。
type ParametersSummary struct {
	Rate            int     `json:"rate"`
	DurationSeconds float64 `json:"duration_seconds"`
}

// TimingSummary 包含测试的最早和最晚时间戳。
type TimingSummary struct {
	Earliest time.Time `json:"earliest"`
	Latest   time.Time `json:"latest"`
}

// RequestsSummary 包含关于请求总数及其成功率的统计信息。
type RequestsSummary struct {
	Count        uint64  `json:"count"`
	SuccessRatio float64 `json:"success_ratio"`
}

// LatencySummary 包含以毫秒为单位的延迟统计信息。
type LatencySummary struct {
	Total float64 `json:"total"`
	Mean  float64 `json:"mean"`
	P50   float64 `json:"p50"`
	P90   float64 `json:"p90"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
	Max   float64 `json:"max"`
	Min   float64 `json:"min"`
}

// BytesSummary 包含关于流入和流出字节数的统计信息。
type BytesSummary struct {
	In  BytesFlowSummary `json:"in"`
	Out BytesFlowSummary `json:"out"`
}

// BytesFlowSummary 包含特定字节流（流入或流出）的统计信息。
type BytesFlowSummary struct {
	Total uint64  `json:"total"`
	Mean  float64 `json:"mean"`
}

// StatusCodesSummary 是状态码及其出现次数的映射。
type StatusCodesSummary map[string]int

// MarshalJSON 实现了 json.Marshaler 接口，以确保稳定的排序。
func (s StatusCodesSummary) MarshalJSON() ([]byte, error) {
	// 提取键并对其进行排序，以保证确定性的 JSON 输出。
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		// 序列化键字符串以处理转义。
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteByte(':')
		buf.WriteString(strconv.Itoa(s[key]))
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// FileExporter 处理将压力测试结果导出到文件。
type FileExporter struct {
	dir string
}

// NewFileExporter 创建一个新的 FileExporter，输出到指定目录。
func NewFileExporter(dir string) *FileExporter {
	return &FileExporter{dir: dir}
}

// Run 表示正在进行的导出运行。
type Run struct {
	meta Meta

	resultsPath string
	summaryPath string

	resultsFile *os.File
	resultsBuf  *bufio.Writer
	resultsCSV  *csv.Writer

	tempResultsPath string
	closed          bool
}

// StartRun 开始一个新的导出运行，创建必要的文件。
func (e *FileExporter) StartRun(meta Meta) (*Run, error) {
	if meta.ID == "" {
		return nil, errors.New("需要导出运行 ID")
	}
	if e.dir == "" {
		return nil, errors.New("需要导出目录")
	}

	resultsPath := filepath.Join(e.dir, resultsFilename)
	summaryPath := filepath.Join(e.dir, summaryFilename(meta.ID))

	// 为结果使用临时文件，以确保 Close 时的原子更新。
	tmpFile, err := os.CreateTemp(e.dir, ".results.csv.")
	if err != nil {
		return nil, fmt.Errorf("无法在 %q 中创建临时结果文件: %w", e.dir, err)
	}
	tempResultsPath := tmpFile.Name()

	// 确保文件具有标准权限。
	if err := tmpFile.Chmod(0o644); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tempResultsPath)
		return nil, fmt.Errorf("无法修改临时结果文件 %q 的权限: %w", tempResultsPath, err)
	}

	var resultsExist bool
	info, err := os.Stat(resultsPath)
	if err == nil {
		if info.IsDir() {
			_ = tmpFile.Close()
			_ = os.Remove(tempResultsPath)
			return nil, fmt.Errorf("结果路径 %q 是一个目录", resultsPath)
		}
		resultsExist = true

		// 如果结果文件已存在，将其内容复制到临时文件中，
		// 以支持在同一目录中追加多个运行的结果。
		src, err := os.Open(resultsPath)
		if err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tempResultsPath)
			return nil, fmt.Errorf("无法打开结果文件 %q: %w", resultsPath, err)
		}
		if _, err := io.Copy(tmpFile, src); err != nil {
			_ = src.Close()
			_ = tmpFile.Close()
			_ = os.Remove(tempResultsPath)
			return nil, fmt.Errorf("无法复制结果文件 %q: %w", resultsPath, err)
		}
		if err := src.Close(); err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tempResultsPath)
			return nil, fmt.Errorf("无法关闭结果文件 %q: %w", resultsPath, err)
		}
	} else if !os.IsNotExist(err) {
		_ = tmpFile.Close()
		_ = os.Remove(tempResultsPath)
		return nil, fmt.Errorf("无法获取结果文件 %q 的状态: %w", resultsPath, err)
	}

	// 设置带缓冲的写入以提高效率。
	buf := bufio.NewWriter(tmpFile)
	writer := csv.NewWriter(buf)

	// 仅在创建新文件时编写 CSV 表头。
	if !resultsExist {
		if err := writer.Write(resultsHeader); err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tempResultsPath)
			return nil, fmt.Errorf("无法将结果表头写入 %q: %w", resultsPath, err)
		}
	}

	return &Run{
		meta:            meta,
		resultsPath:     resultsPath,
		summaryPath:     summaryPath,
		resultsFile:     tmpFile,
		resultsBuf:      buf,
		resultsCSV:      writer,
		tempResultsPath: tempResultsPath,
	}, nil
}

// WriteResult 将单个结果写入结果 CSV 文件。
func (r *Run) WriteResult(res Result) error {
	if r.closed {
		return errors.New("导出运行已关闭")
	}

	// 如果特定结果字段缺失，则回退到元数据信息。
	url := res.URL
	if url == "" {
		url = r.meta.TargetURL
	}
	method := res.Method
	if method == "" {
		method = r.meta.Method
	}

	// 根据 resultsHeader 格式化记录: [id, timestamp, latency_ns, url, method, status_code]
	record := []string{
		r.meta.ID,
		res.Timestamp.Format(time.RFC3339Nano),
		formatLatencyNS(res.LatencyNS),
		url,
		method,
		strconv.FormatUint(uint64(res.StatusCode), 10),
	}

	if err := r.resultsCSV.Write(record); err != nil {
		_ = r.Abort() // 写入失败时进行清理。
		return fmt.Errorf("无法将结果写入 %q: %w", r.resultsPath, err)
	}
	return nil
}

// Close 完成导出运行，保存汇总信息并最终确定文件。
func (r *Run) Close(summary Summary) error {
	if r.closed {
		return errors.New("导出运行已关闭")
	}

	// 确保所有数据都从 CSV 和缓冲区刷新到操作系统文件。
	r.resultsCSV.Flush()
	if err := r.resultsCSV.Error(); err != nil {
		_ = r.Abort()
		return fmt.Errorf("无法将结果刷新到 %q: %w", r.resultsPath, err)
	}
	if err := r.resultsBuf.Flush(); err != nil {
		_ = r.Abort()
		return fmt.Errorf("无法将结果缓冲区刷新到 %q: %w", r.resultsPath, err)
	}

	// 确保数据已持久化到磁盘。
	if err := r.resultsFile.Sync(); err != nil {
		_ = r.Abort()
		return fmt.Errorf("无法同步结果文件 %q: %w", r.resultsPath, err)
	}

	// 在重命名之前关闭文件。
	if err := r.resultsFile.Close(); err != nil {
		_ = r.Abort()
		return fmt.Errorf("无法关闭结果文件 %q: %w", r.resultsPath, err)
	}

	// 原子地用新文件替换旧结果文件。
	if err := os.Rename(r.tempResultsPath, r.resultsPath); err != nil {
		_ = os.Remove(r.tempResultsPath)
		return fmt.Errorf("无法替换结果文件 %q: %w", r.resultsPath, err)
	}

	// 写入最终的汇总 JSON。
	if err := writeSummary(r.summaryPath, summary); err != nil {
		return err
	}

	r.closed = true
	return nil
}

// Abort 取消导出运行，清理临时文件。
func (r *Run) Abort() error {
	if r.closed {
		return nil
	}
	_ = r.resultsFile.Close()

	// 如果临时文件存在，则将其清理。
	if err := os.Remove(r.tempResultsPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	r.closed = true
	return nil
}

// writeSummary 以原子方式将给定的汇总信息写入指定的文件路径。
func writeSummary(path string, summary Summary) error {
	dir := filepath.Dir(path)

	// 使用临时文件进行原子 JSON 写入。
	tmpFile, err := os.CreateTemp(dir, ".summary.")
	if err != nil {
		return fmt.Errorf("无法在 %q 中创建临时汇总文件: %w", dir, err)
	}
	tmpPath := tmpFile.Name()

	if err := tmpFile.Chmod(0o644); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("无法修改临时汇总文件 %q 的权限: %w", tmpPath, err)
	}

	// 使用缩进进行编码以提高可读性。
	enc := json.NewEncoder(tmpFile)
	enc.SetIndent("", "  ")
	if err := enc.Encode(summary); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("无法将汇总信息编码到 %q: %w", path, err)
	}

	// 刷新到磁盘并关闭。
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("无法同步汇总文件 %q: %w", path, err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("无法关闭汇总文件 %q: %w", path, err)
	}

	// 替换最终文件。
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("无法替换汇总文件 %q: %w", path, err)
	}
	return nil
}

// formatLatencyNS 将纳秒延迟格式化为字符串。
// 通过返回空字符串来处理 NaN 和无穷大。
func formatLatencyNS(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return ""
	}
	return strconv.FormatInt(int64(v), 10)
}

// summaryFilename 根据给定的 ID 返回汇总文件的文件名。
func summaryFilename(id string) string {
	return fmt.Sprintf("summary-%s.json", id)
}