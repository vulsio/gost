package util

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	pb "github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	"github.com/parnurzeal/gorequest"
	"github.com/spf13/viper"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
)

// Unique return unique elements
func Unique[T comparable](s []T) []T {
	m := map[T]struct{}{}
	for _, v := range s {
		m[v] = struct{}{}
	}
	return maps.Keys(m)
}

// GenWorkers generate workers
func GenWorkers(num, wait int) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		go func() {
			for f := range tasks {
				f()
				time.Sleep(time.Duration(wait) * time.Second)
			}
		}()
	}
	return tasks
}

// GetDefaultLogDir returns default log directory
func GetDefaultLogDir() string {
	defaultLogDir := "/var/log/gost"
	if runtime.GOOS == "windows" {
		defaultLogDir = filepath.Join(os.Getenv("APPDATA"), "gost")
	}
	return defaultLogDir
}

// TrimSpaceNewline deletes space character and newline character(CR/LF)
func TrimSpaceNewline(str string) string {
	str = strings.TrimSpace(str)
	return strings.Trim(str, "\r\n")
}

// FetchURL returns HTTP response body
func FetchURL(url string) ([]byte, error) {
	resp, body, err := gorequest.New().Proxy(viper.GetString("http-proxy")).Get(url).Type("text").EndBytes()
	if len(err) > 0 || resp == nil || resp.StatusCode != 200 {
		return nil, xerrors.Errorf("HTTP error. url: %s, err: %w", url, err)
	}
	return body, nil
}

// FetchConcurrently fetches concurrently
func FetchConcurrently(urls []string, concurrency, wait int) (responses [][]byte, err error) {
	reqChan := make(chan string, len(urls))
	resChan := make(chan []byte, len(urls))
	errChan := make(chan error, len(urls))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, url := range urls {
			reqChan <- url
		}
	}()

	bar := pb.StartNew(len(urls))
	tasks := GenWorkers(concurrency, wait)
	for range urls {
		tasks <- func() {
			url := <-reqChan
			var err error
			for i := 1; i <= 3; i++ {
				var res []byte
				res, err = FetchURL(url)
				if err == nil {
					resChan <- res
					return
				}
				time.Sleep(time.Duration(i*2) * time.Second)
			}
			errChan <- err
		}
		bar.Increment()
	}
	bar.Finish()

	errs := []error{}
	timeout := time.After(10 * 60 * time.Second)
	for range urls {
		select {
		case res := <-resChan:
			responses = append(responses, res)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return nil, fmt.Errorf("Timeout Fetching URL")
		}
	}
	if 0 < len(errs) {
		return nil, fmt.Errorf("%s", errs)

	}
	return responses, nil
}

// SetLogger set logger
func SetLogger(logToFile bool, logDir string, debug, logJSON bool) error {
	stderrHandler := log15.StderrHandler
	logFormat := log15.LogfmtFormat()
	if logJSON {
		logFormat = log15.JsonFormatEx(false, true)
		stderrHandler = log15.StreamHandler(os.Stderr, logFormat)
	}

	lvlHandler := log15.LvlFilterHandler(log15.LvlInfo, stderrHandler)
	if debug {
		lvlHandler = log15.LvlFilterHandler(log15.LvlDebug, stderrHandler)
	}

	var handler log15.Handler
	if logToFile {
		if _, err := os.Stat(logDir); err != nil {
			if os.IsNotExist(err) {
				if err := os.Mkdir(logDir, 0700); err != nil {
					return xerrors.Errorf("Failed to create log directory. err: %w", err)
				}
			} else {
				return xerrors.Errorf("Failed to check log directory. err: %w", err)
			}
		}

		logPath := filepath.Join(logDir, "gost.log")
		if _, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err != nil {
			return xerrors.Errorf("Failed to open a log file. err: %w", err)
		}
		handler = log15.MultiHandler(
			log15.Must.FileHandler(logPath, logFormat),
			lvlHandler,
		)
	} else {
		handler = lvlHandler
	}
	log15.Root().SetHandler(handler)
	return nil
}

// Major returns major version
func Major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}

// CacheDir return cache dir path string
func CacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "gost")
}

// FileWalk walks the file tree rooted at root
func FileWalk(root string, targetFiles map[string]struct{}, walkFn func(r io.Reader, path string) error) error {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return xerrors.Errorf("prevent panic by handling failure accessing a path %q: %w\n", path, err)
		}

		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return xerrors.Errorf("error in filepath rel: %w", err)
		}

		if _, ok := targetFiles[rel]; !ok {
			return nil
		}

		if info.Size() == 0 {
			log15.Debug("invalid size: %s", path)
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("failed to open file: %w", err)
		}
		defer f.Close()

		return walkFn(f, path)
	})
	if err != nil {
		return xerrors.Errorf("error in file walk: %w", err)
	}
	return nil
}

// IsCommandAvailable check if command is available.
func IsCommandAvailable(name string) bool {
	cmd := exec.Command(name, "--help")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// Exists check if path exists
func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

// Exec run the command
func Exec(command string, args []string) (string, error) {
	cmd := exec.Command(command, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		log15.Debug(stderrBuf.String())
		return "", xerrors.Errorf("failed to exec: %w", err)
	}
	return stdoutBuf.String(), nil
}

// FilterTargets filter targets
func FilterTargets(prefixPath string, targets map[string]struct{}) (map[string]struct{}, error) {
	filtered := map[string]struct{}{}
	for filename := range targets {
		if strings.HasPrefix(filename, prefixPath) {
			rel, err := filepath.Rel(prefixPath, filename)
			if err != nil {
				return nil, xerrors.Errorf("error in filepath rel: %w", err)
			}
			if strings.HasPrefix(rel, "../") {
				continue
			}
			filtered[rel] = struct{}{}
		}
	}
	return filtered, nil
}

var (
	// Quiet manages the display of NewSpinner, ProgressBar
	Quiet = false
)

// Spinner has Spinner client
type Spinner struct {
	client *spinner.Spinner
}

// NewSpinner creates a Spinner
func NewSpinner(suffix string) *Spinner {
	if Quiet {
		return &Spinner{}
	}
	s := spinner.New(spinner.CharSets[36], 100*time.Millisecond)
	s.Suffix = suffix
	return &Spinner{client: s}
}

// Start will start Spinner
func (s *Spinner) Start() {
	if s.client == nil {
		return
	}
	s.client.Start()
}

// Stop will stop the Spinner
func (s *Spinner) Stop() {
	if s.client == nil {
		return
	}
	s.client.Stop()
}

// ProgressBar has ProgressBar client
type ProgressBar struct {
	client *pb.ProgressBar
}

// PbStartNew creates a ProgressBar
func PbStartNew(total int) *ProgressBar {
	if Quiet {
		return &ProgressBar{}
	}
	bar := pb.StartNew(total)
	return &ProgressBar{client: bar}
}

// Increment increments the ProgressBar
func (p *ProgressBar) Increment() {
	if p.client == nil {
		return
	}
	p.client.Increment()
}

// Finish to exit the ProgressBar
func (p *ProgressBar) Finish() {
	if p.client == nil {
		return
	}
	p.client.Finish()
}
