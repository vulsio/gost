.PHONY: \
	all \
	build \
	install \
	lint \
	golangci \
	vet \
	fmt \
	fmtcheck \
	pretest \
	test \
	integration \
	cov \
	clean \
	build-integration \
	clean-integration \
	fetch-rdb \
	fetch-redis \
	diff-cveid \
	diff-package \
	diff-server-rdb \
	diff-server-redis \
	diff-server-rdb-redis

SRCS = $(shell git ls-files '*.go')
PKGS = $(shell go list ./...)
VERSION := $(shell git describe --tags --abbrev=0)
REVISION := $(shell git rev-parse --short HEAD)
LDFLAGS := -X 'github.com/vulsio/gost/config.Version=$(VERSION)' \
	-X 'github.com/vulsio/gost/config.Revision=$(REVISION)'
GO := CGO_ENABLED=0 go

all: build test

build: main.go
	$(GO) build -ldflags "$(LDFLAGS)" -o gost  $<

install: main.go
	$(GO) install -ldflags "$(LDFLAGS)"

lint:
	go install github.com/mgechev/revive@latest
	revive -config ./.revive.toml -formatter plain $(PKGS)

golangci:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

vet:
	echo $(PKGS) | xargs env $(GO) vet || exit;

fmt:
	gofmt -s -w $(SRCS)

fmtcheck:
	$(foreach file,$(SRCS),gofmt -s -d $(file);)

pretest: lint vet fmtcheck

test: pretest
	$(GO) test -cover -v ./... || exit;

cov:
	@ go get -v github.com/axw/gocov/gocov
	@ go get golang.org/x/tools/cmd/cover
	gocov test | gocov report

clean:
	$(foreach pkg,$(PKGS),go clean $(pkg) || exit;)

BRANCH := $(shell git symbolic-ref --short HEAD)
build-integration:
	@ git stash save
	$(GO) build -ldflags "$(LDFLAGS)" -o integration/gost.new
	git checkout $(shell git describe --tags --abbrev=0)
	@git reset --hard
	$(GO) build -ldflags "$(LDFLAGS)" -o integration/gost.old
	git checkout $(BRANCH)
	-@ git stash apply stash@{0} && git stash drop stash@{0}

clean-integration:
	-pkill gost.old
	-pkill gost.new
	-rm integration/gost.old integration/gost.new integration/gost.old.sqlite3 integration/gost.new.sqlite3
	-rm -rf integration/diff
	-docker kill redis-old redis-new
	-docker rm redis-old redis-new

fetch-rdb:
	integration/gost.old fetch debian --dbpath=integration/gost.old.sqlite3 --batch-size 500
	integration/gost.old fetch ubuntu --dbpath=integration/gost.old.sqlite3 --batch-size 15
	integration/gost.old fetch redhat --dbpath=integration/gost.old.sqlite3 --batch-size 500
	# integration/gost.old fetch microsoft --dbpath=integration/gost.old.sqlite3 --batch-size 200 --apikey=<APIKEY>
	
	integration/gost.new fetch debian --dbpath=integration/gost.new.sqlite3 --batch-size 500
	integration/gost.new fetch ubuntu --dbpath=integration/gost.new.sqlite3 --batch-size 15
	integration/gost.new fetch redhat --dbpath=integration/gost.new.sqlite3 --batch-size 500
	# integration/gost.new fetch microsoft --dbpath=integration/gost.new.sqlite3 --batch-size 200 --apikey=<APIKEY>

fetch-redis:
	docker run --name redis-old -d -p 127.0.0.1:6379:6379 redis
	docker run --name redis-new -d -p 127.0.0.1:6380:6379 redis

	integration/gost.old fetch debian --dbtype redis --dbpath "redis://127.0.0.1:6379/0"
	integration/gost.old fetch ubuntu --dbtype redis --dbpath "redis://127.0.0.1:6379/0"
	integration/gost.old fetch redhat --dbtype redis --dbpath "redis://127.0.0.1:6379/0"
	# integration/gost.old fetch microsoft --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --apikey=<APIKEY>

	integration/gost.new fetch debian --dbtype redis --dbpath "redis://127.0.0.1:6380/0"
	integration/gost.new fetch ubuntu --dbtype redis --dbpath "redis://127.0.0.1:6380/0"
	integration/gost.new fetch redhat --dbtype redis --dbpath "redis://127.0.0.1:6380/0"
	# integration/gost.new fetch microsoft --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --apikey=<APIKEY>

diff-cveid:
	@ python integration/diff_server_mode.py cveid --sample_rate 0.01 debian
	@ python integration/diff_server_mode.py cveid --sample_rate 0.01 ubuntu
	@ python integration/diff_server_mode.py cveid --sample_rate 0.01 redhat
	# @ python integration/diff_server_mode.py cveid --sample_rate 0.01 microsoft

diff-cveids:
	@ python integration/diff_server_mode.py cveids --sample_rate 0.01 debian
	@ python integration/diff_server_mode.py cveids --sample_rate 0.01 ubuntu
	@ python integration/diff_server_mode.py cveids --sample_rate 0.01 redhat
	# @ python integration/diff_server_mode.py cveids --sample_rate 0.01 microsoft

diff-package:
	@ python integration/diff_server_mode.py package --sample_rate 0.01 debian
	@ python integration/diff_server_mode.py package --sample_rate 0.01 ubuntu
	@ python integration/diff_server_mode.py package --sample_rate 0.01 redhat
	# @ python integration/diff_server_mode.py kbid --sample_rate 0.01 microsoft

diff-server-rdb:
	integration/gost.old server --dbpath=integration/gost.old.sqlite3 --port 1325 > /dev/null 2>&1 &
	integration/gost.new server --dbpath=integration/gost.new.sqlite3 --port 1326 > /dev/null 2>&1 &
	make diff-cveid
	make diff-cveids
	make diff-package
	pkill gost.old 
	pkill gost.new

diff-server-redis:
	integration/gost.old server --dbtype redis --dbpath "redis://127.0.0.1:6379/0" --port 1325 > /dev/null 2>&1 &
	integration/gost.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null 2>&1 &
	make diff-cveid
	make diff-cveids
	make diff-package
	pkill gost.old 
	pkill gost.new

diff-server-rdb-redis:
	integration/gost.new server --dbpath=integration/gost.new.sqlite3 --port 1325 > /dev/null 2>&1 &
	integration/gost.new server --dbtype redis --dbpath "redis://127.0.0.1:6380/0" --port 1326 > /dev/null 2>&1 &
	make diff-cveid
	make diff-cveids
	make diff-package
	pkill gost.new
