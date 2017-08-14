package util

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/parnurzeal/gorequest"
	"github.com/spf13/viper"
	pb "gopkg.in/cheggaaa/pb.v1"
)

// GenWorkers generate workders
func GenWorkers(num int) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		go func() {
			for f := range tasks {
				f()
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

// DeleteNil deletes nil in errs
func DeleteNil(errs []error) (new []error) {
	for _, err := range errs {
		if err != nil {
			new = append(new, err)
		}
	}
	return new
}

// TrimSpaceNewline deletes space character and newline character(CR/LF)
func TrimSpaceNewline(str string) string {
	str = strings.TrimSpace(str)
	return strings.Trim(str, "\r\n")
}

// FetchURL returns HTTP response body
func FetchURL(url string) (string, error) {
	var errs []error
	httpProxy := viper.GetString("http-proxy")

	resp, body, errs := gorequest.New().Proxy(httpProxy).Get(url).Type("text").End()
	if len(errs) > 0 || resp == nil || resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP error. errs: %v, url: %s", errs, url)
	}
	return body, nil
}

func FetchConcurrently(urls []string, concurrency int) (responses []string, err error) {
	reqChan := make(chan string, len(urls))
	resChan := make(chan string, len(urls))
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
	tasks := GenWorkers(concurrency)
	for range urls {
		tasks <- func() {
			select {
			case url := <-reqChan:
				res, err := FetchURL(url)
				if err != nil {
					errChan <- err
					return
				}
				resChan <- res
			}
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
			return []string{}, fmt.Errorf("Timeout Fetching URL")
		}
	}
	if 0 < len(errs) {
		return []string{}, fmt.Errorf("%s", errs)

	}
	return responses, nil
}
