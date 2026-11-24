// vercmp_probe 是原生版本比较差分测试的 Go 侧探测程序。
//
// 从 stdin 读取 "a<TAB>b" 行，调用 internal/version.Compare 输出符号：
//
//	-1  a < b
//	 0  a == b
//	 1  a > b
//	ERR a 或 b 非法（附带原因）
//
// 用法：go run ./tests/vercmp_probe.go <manager> < cases.txt
//
// 注意：本程序仅供 tests/version_diff.sh 在 CI 容器内调用，
// 不随主二进制发布，也不在主测试路径中运行。
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/version"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: vercmp_probe <dpkg|rpm|apk|pacman>")
		os.Exit(2)
	}
	manager := domain.PackageManager(os.Args[1])

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 剥离 #DIFF 前缀（语义差异用例，脚本单独处理）
		if strings.HasPrefix(line, "#DIFF ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "#DIFF "))
		}

		fields := strings.Split(line, "\t")
		if len(fields) != 2 {
			fmt.Printf("ERR\tbad input: %q\n", line)
			continue
		}
		a, b := strings.TrimSpace(fields[0]), strings.TrimSpace(fields[1])

		cmp, err := version.Compare(manager, a, b)
		if err != nil {
			fmt.Printf("ERR\t%v\n", err)
			continue
		}
		fmt.Printf("%d\t%s\t%s\n", cmp, a, b)
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "read error: %v\n", err)
		os.Exit(1)
	}
}
