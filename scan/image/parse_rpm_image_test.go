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
			name:      "测试openeuler镜像",
			imagePath: "openeuler/openeuler",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ParseImageFile(test.imagePath)
			if err != nil {
				fmt.Println(err)
			}
		})
	}
}
