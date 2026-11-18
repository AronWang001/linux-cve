# Linux CVE Fix v2.0 — 常用构建目标
#
# 无 make 环境时等价的直接命令：
#   go build ./...
#   go test ./...
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/linux-cve ./cmd/linux-cve

BINARY     := linux-cve
MODULE     := github.com/AronWang001/linux-cve-2026-98432-fix
VERSION    ?= 2.0.0-dev
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DIST       := dist

LDFLAGS := -s -w \
	-X $(MODULE)/internal/buildinfo.Version=$(VERSION) \
	-X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) \
	-X $(MODULE)/internal/buildinfo.BuildDate=$(BUILD_DATE)

.PHONY: all build build-linux build-arm64 vet test test-race fmt tidy check clean

all: check build

## build: 构建当前平台二进制
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY) ./cmd/linux-cve

## build-linux: 构建 linux/amd64（纯静态，无 cgo）
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64 ./cmd/linux-cve

## build-arm64: 构建 linux/arm64
build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-arm64 ./cmd/linux-cve

## vet: 静态检查
vet:
	go vet ./...

## test: 单元测试
test:
	go test ./...

## test-race: 竞态检测（需要可用的 C 工具链）
test-race:
	go test -race ./...

## fmt: 格式化
fmt:
	gofmt -l -w ./cmd ./internal

## tidy: 整理依赖
tidy:
	go mod tidy

## check: 发布前必过的本地检查
check:
	@out=$$(gofmt -l ./cmd ./internal); if [ -n "$$out" ]; then echo "以下文件未格式化:"; echo "$$out"; exit 1; fi
	go vet ./...
	go test ./...

## clean: 清除构建产物
clean:
	rm -rf $(DIST)
