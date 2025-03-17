package image

import (
	"fmt"
	"testing"
)

func TestParseImageFile(t *testing.T) {

	tests := []struct {
		name      string
		imagePath string
	}{
		{
			name:      "测试fedora镜像",
			imagePath: "f7b31b439cbe274a1f3402632e9bfd81f6647a5ca4097a5f99821832d643826d",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			fmt.Println("开始处理镜像...")

			err := ParseImageFile(test.imagePath)
			// 错误处理：如果有错误，使测试失败
			if err != nil {
				t.Fatalf("ParseImageFile() 失败: %v", err)
				return
			}

		})
	}
}
