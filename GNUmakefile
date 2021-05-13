.PHONY: \
	build \
	install \
	all \
	vendor \
	lint \
	vet \
	fmt \
	fmtcheck \
	pretest \
	test \
	integration \
	cov \
	clean

SRCS = $(shell git ls-files '*.go')
PKGS = $(shell go list ./...)
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
LDFLAGS := -X 'github.com/knqyf263/gost/config.Version=$(VERSION)' \
	-X 'github.com/knqyf263/gost/config.Revision=$(REVISION)'
GO := GO111MODULE=on go
GO_OFF := GO111MODULE=off go

all: build

build: main.go pretest
	$(GO) build -ldflags "$(LDFLAGS)" -o gost  $<

install: main.go pretest
	$(GO) install -ldflags "$(LDFLAGS)"

b: 	main.go pretest
	$(GO) build -ldflags "$(LDFLAGS)" -o gost $<

lint:
	$(GO_OFF) get -u golang.org/x/lint/golint
	golint $(PKGS)

vet:
	echo $(PKGS) | xargs env $(GO) vet || exit;

fmt:
	gofmt -s -w $(SRCS)

mlint:
	$(foreach file,$(SRCS),gometalinter $(file) || exit;)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -s -d $(file);)

pretest: lint vet fmtcheck

test: 
	$(GO) test -cover -v ./... || exit;

unused:
	$(foreach pkg,$(PKGS),unused $(pkg);)

integration:
	go test -tags docker_integration -run TestIntegration -v

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report

clean:
	$(foreach pkg,$(PKGS),go clean $(pkg) || exit;)

diff-server-all:
	@ python integration/diff_server_mode.py debian
	@ python integration/diff_server_mode.py redhat
	@ python integration/diff_server_mode.py microsoft

