package domain

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestDomainDependsOnStdlibOnly 保证 domain 包零外部依赖。
//
// 这是架构约束（docs/architecture.md §8：domain 不 import 任何内部包），
// 用测试固化，防止后续阶段把数据库/网络细节渗进领域层。
func TestDomainDependsOnStdlibOnly(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("读取当前目录失败: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			// 含点号的一级路径即第三方或内部模块
			if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
				t.Errorf("%s 引入了非标准库依赖 %q：domain 必须保持零外部依赖", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("未检查到任何源文件，测试无效")
	}
}
