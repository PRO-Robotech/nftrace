export GOSUMDB=off
export GO111MODULE=on

$(value $(shell [ ! -d "$(CURDIR)/bin" ] && mkdir -p "$(CURDIR)/bin"))
export GOBIN=$(CURDIR)/bin

GO?=$(shell which go)
GIT_TAG:=$(shell git describe --exact-match --abbrev=0 --tags 2> /dev/null)
GIT_HASH:=$(shell git log --format="%h" -n 1 2> /dev/null)
GIT_BRANCH:=$(shell git branch 2> /dev/null | grep '*' | cut -f2 -d' ')
GO_VERSION:=$(shell go version | sed -E 's/.* go(.*) .*/\1/g')
BUILD_TS:=$(shell date +%FT%T%z)
VERSION:=$(shell cat ./VERSION 2> /dev/null | sed -n "1p")

PROJECT:=NFTRACE
APP?=trace-monitor
APP_NAME?=$(PROJECT)/$(APP)
APP_VERSION:=$(if $(VERSION),$(VERSION),$(if $(GIT_TAG),$(GIT_TAG),$(GIT_BRANCH)))

.NOTPARALLEL:

.PHONY: help
help: ##display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

GOLANGCI_BIN:=$(GOBIN)/golangci-lint
GOLANGCI_REPO=https://github.com/golangci/golangci-lint
GOLANGCI_LATEST_VERSION:= $(shell git ls-remote --tags --refs --sort='v:refname' $(GOLANGCI_REPO)|tail -1|egrep -o "v[0-9]+.*")
ifneq ($(wildcard $(GOLANGCI_BIN)),)
	GOLANGCI_CUR_VERSION=v$(shell $(GOLANGCI_BIN) --version|sed -E 's/.*version (.*) built.*/\1/g')	
else
	GOLANGCI_CUR_VERSION=
endif

.PHONY: .install-linter
.install-linter:
ifeq ($(filter $(GOLANGCI_CUR_VERSION), $(GOLANGCI_LATEST_VERSION)),)
	$(info Installing GOLANGCI-LINT $(GOLANGCI_LATEST_VERSION)...)
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOBIN) $(GOLANGCI_LATEST_VERSION)
	@chmod +x $(GOLANGCI_BIN)
else
	@echo 1 >/dev/null
endif

.PHONY: lint
lint: ##run full lint
	@echo full lint... && \
	$(MAKE) .install-linter && \
	$(GOLANGCI_BIN) cache clean && \
	$(GOLANGCI_BIN) run --timeout=120s --config=$(CURDIR)/.golangci.yaml -v $(CURDIR)/... &&\
	echo -=OK=-

.PHONY: go-deps
go-deps: ##install golang dependencies
	@echo check go modules dependencies ... && \
	$(GO) mod tidy && \
 	GOWORK=off $(GO) mod vendor && \
	$(GO) mod verify && \
	echo -=OK=-

.PHONY: test
test: ##run tests
	@echo running tests... && \
	$(GO) clean -testcache && \
	$(GO) test -v -race ./... && \
	echo -=OK=-

platform?=$(shell $(GO) env GOOS)/$(shell $(GO) env GOARCH)
os?=$(strip $(filter linux darwin,$(word 1,$(subst /, ,$(platform)))))
arch?=$(strip $(filter amd64 arm64,$(word 2,$(subst /, ,$(platform)))))
OUT?=$(CURDIR)/bin/$(APP)

APP_IDENTITY?=github.com/H-BF/corlib/app/identity
LDFLAGS?=-X '$(APP_IDENTITY).Name=$(APP_NAME)'\
         -X '$(APP_IDENTITY).Version=$(APP_VERSION)'\
         -X '$(APP_IDENTITY).BuildTS=$(BUILD_TS)'\
         -X '$(APP_IDENTITY).BuildBranch=$(GIT_BRANCH)'\
         -X '$(APP_IDENTITY).BuildHash=$(GIT_HASH)'\
         -X '$(APP_IDENTITY).BuildTag=$(GIT_TAG)'\

BPF2GO:=$(GOBIN)/bpf2go

.PHONY: .install-bpf2go
.install-bpf2go:
ifneq ($(wildcard $(BPF2GO)),)
	@echo >/dev/null
else
	@echo installing bpf2go && \
	GOBIN=$(GOBIN) $(GO) install github.com/cilium/ebpf/cmd/bpf2go@v0.16.0 && \
	echo -=OK=-
endif

BPFDIR:=$(CURDIR)/internal/collectors/ebpf

.PHONY: .ebpf
.ebpf: | .install-bpf2go ##build ebpf program. Usage: make .ebpf [arch=<amd64|arm64>]
ifeq ($(filter amd64 arm64,$(arch)),)
	$(error arch=$(arch) but must be in [amd64|arm64])
endif
ifneq ('$(os)','linux')
	@$(MAKE) $@ os=linux
else
	@echo build ebpf program for OS/ARCH='$(os)'/'$(arch)' ... && \
	$(BPF2GO) -output-dir $(BPFDIR) -tags $(os) -type trace_info -go-package=ebpf -target $(arch) bpf $(BPFDIR)/ebpf-src/nftrace.c -- -I$(BPFDIR)/ebpf-src/ && \
	echo -=OK=-
endif

.PHONY: .install-mockery
.install-mockery:
ifeq ($(filter $(MOCKERY_CUR_VERSION), $(MOCKERY_LATEST_VERSION)),)
	@echo installing 'mockery' $(MOCKERY_LATEST_VERSION) util... && \
	GOBIN=$(GOBIN) $(GO) install github.com/vektra/mockery/v2@$(MOCKERY_LATEST_VERSION)
else
	@echo 'mockery is up to date: $(MOCKERY_CUR_VERSION)'
endif

.PHONY:
generate:
	@echo executing go generate for all subdirs ... && \
	 $(GO) generate ./... && \
	echo -=OK=-

.PHONY: trace-monitor
trace-monitor: ##build trace-monitor. Usage: make trace-monitor [arch=<amd64|arm64>]
ifeq ($(filter amd64 arm64,$(arch)),)
	$(error arch=$(arch) but must be in [amd64|arm64])
endif
ifneq ('$(os)','linux')
	@$(MAKE) $@ os=linux
else
	@$(MAKE) go-deps && \
	$(MAKE) .ebpf arch=$(arch) && \
	echo build '$(APP)' for OS/ARCH='$(os)'/'$(arch)' ... && \
	echo into '$(OUT)' && \
	env GOOS=$(os) GOARCH=$(arch) CGO_ENABLED=0 \
	$(GO) build -ldflags="$(LDFLAGS)" -o $(OUT) $(CURDIR)/cmd/$(APP) &&\
	echo -=OK=-
endif

.PHONY: rule-watcher
rule-watcher: ##build rule-watcher. Usage: make rule-watcher [arch=<amd64|arm64>]
rule-watcher: APP=rule-watcher
rule-watcher: OUT=$(CURDIR)/bin/$(APP)
rule-watcher:
ifeq ($(filter amd64 arm64,$(arch)),)
	$(error arch=$(arch) but must be in [amd64|arm64])
endif
ifneq ('$(os)','linux')
	@$(MAKE) $@ os=linux
else
	@$(MAKE) go-deps && \
	echo build '$(APP)' for OS/ARCH='$(os)'/'$(arch)' ... && \
	echo into '$(OUT)' && \
	env GOOS=$(os) GOARCH=$(arch) CGO_ENABLED=0 \
	$(GO) build -ldflags="$(LDFLAGS)" -o $(OUT) $(CURDIR)/cmd/$(APP) &&\
	echo -=OK=-
endif


.PHONY: .clean-ebpf
.clean-ebpf:
	rm -rf $(BPFDIR)/ebpf-src/*.o
	rm -rf $(BPFDIR)/*.o

.PHONY: clean
clean: | .clean-ebpf ##clean project
clean:
	rm -rf $(CURDIR)/bin/
	rm -rf $(CURDIR)/vendor/