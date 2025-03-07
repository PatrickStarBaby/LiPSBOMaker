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

	// 清理之前可能存在的测试文件
	cleanupOldTestFiles()

	tests := []struct {
		name      string
		imagePath string
	}{
		{
			name:      "测试ubuntu镜像",
			imagePath: "edbfe74c41f8a3501ce542e137cf28ea04dd03e6df8c9d66519b6ad761c2598a",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
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

// 清理旧的测试文件
func cleanupOldTestFiles() {
	files, err := os.ReadDir(".")
	if err != nil {
		return
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), "sbom_result_") && strings.HasSuffix(file.Name(), ".json") {
			os.Remove(file.Name())
		}
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
