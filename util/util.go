package util

import (
	"fmt"
	"io"
	"iter"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/inconshreveable/log15"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"
)

// Unique return unique elements
func Unique[T comparable](s []T) []T {
	m := map[T]struct{}{}
	for _, v := range s {
		m[v] = struct{}{}
	}
	return slices.Collect(maps.Keys(m))
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

// FetchURL returns HTTP response
func FetchURL(fetchURL string) (*http.Response, error) {
	client := &http.Client{}
	if proxy := viper.GetString("http-proxy"); proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, xerrors.Errorf("Failed to parse proxy URL. proxy: %s, err: %w", proxy, err)
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}

	req, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return nil, xerrors.Errorf("Failed to create HTTP request. url: %s, err: %w", fetchURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, xerrors.Errorf("Failed to send HTTP request. url: %s, err: %w", fetchURL, err)
	}

	return resp, nil
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

	bar := pb.StartNew(len(urls)).SetWriter(func() io.Writer {
		if viper.GetBool("log-json") {
			return io.Discard
		}
		return os.Stderr
	}())
	tasks := GenWorkers(concurrency, wait)
	for range urls {
		tasks <- func() {
			url := <-reqChan
			var err error
			for i := 1; i <= 3; i++ {
				var res []byte
				res, err = func() ([]byte, error) {
					resp, err := FetchURL(url)
					if err != nil {
						return nil, xerrors.Errorf("Failed to fetch URL. url: %s, err: %w", url, err)
					}
					defer resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						return nil, xerrors.Errorf("Failed to fetch URL. url: %s, err: status code: %d", url, resp.StatusCode)
					}

					bs, err := io.ReadAll(resp.Body)
					if err != nil {
						return nil, xerrors.Errorf("Failed to read response body. url: %s, err: %w", url, err)
					}

					return bs, nil
				}()
				if err != nil {
					time.Sleep(time.Duration(i*2) * time.Second)
					continue
				}
				resChan <- res
				return
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

// Chunk chunks the sequence into n-sized chunks
// Note: slices.Chunk doesn't support iterators as of Go 1.23.
// https://pkg.go.dev/slices#Chunk
func Chunk[T any](s iter.Seq2[T, error], n int) iter.Seq2[[]T, error] {
	return func(yield func([]T, error) bool) {
		if n < 1 {
			if !yield(nil, xerrors.New("cannot be less than 1")) {
				return
			}
		}

		chunk := make([]T, 0, n)
		for t, err := range s {
			if err != nil && !yield(nil, err) {
				return
			}
			chunk = append(chunk, t)
			if len(chunk) != n {
				continue
			}

			if !yield(chunk, nil) {
				return
			}
			chunk = chunk[:0]
		}

		if len(chunk) > 0 {
			if !yield(chunk, nil) {
				return
			}
		}
	}
}
