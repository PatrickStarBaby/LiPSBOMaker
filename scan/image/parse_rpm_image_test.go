package image

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseImageFile(t *testing.T) {
	// 检查是否启用了CGO，SQLite驱动需要CGO
	if os.Getenv("CGO_ENABLED") == "0" {
		t.Skip("此测试需要启用CGO才能使用SQLite")
	}

	// 记录测试开始时间，用于稍后检查文件
	testStartTime := time.Now()

	tests := []struct {
		name      string
		imagePath string
	}{
		{
			name:      "测试debian镜像",
			imagePath: "debian",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// 移除超时设置，允许测试运行任意长的时间以处理所有数据
			fmt.Println("开始处理镜像，将处理所有包和依赖关系，这可能需要较长时间...")

			err := ParseImageFile(test.imagePath)
			// 错误处理：如果有错误，使测试失败
			if err != nil {
				t.Fatalf("ParseImageFile() 失败: %v", err)
				return
			}

			// 验证是否生成了文件
			found := checkForGeneratedFiles(testStartTime)
			if !found {
				t.Errorf("测试执行后没有找到生成的JSON文件")
			} else {
				t.Logf("成功找到生成的JSON文件")
			}
		})
	}
}

// 检查是否生成了文件
func checkForGeneratedFiles(since time.Time) bool {
	files, err := os.ReadDir(".")
	if err != nil {
		return false
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "sbom_result_") && strings.HasSuffix(file.Name(), ".json") {
			// 检查文件是否在测试开始后创建
			info, err := file.Info()
			if err == nil && info.ModTime().After(since) {
				fmt.Printf("找到生成的文件: %s\n", file.Name())
				return true
			}
		}
	}

	return false
}
