package release

import (
	"fmt"
	"testing"
)

func TestParseReleaseRpmFile(t *testing.T) {
	tests := []struct {
		rpmFilePath string
	}{
		{
			rpmFilePath: "./test-fixtures/bash-5.2.15-9.oe2403.x86_64-after-supplement.rpm", //这个是嵌入buildEnv.json文件之后的rpm包
		},
		{
			rpmFilePath: "./test-fixtures/tzdata-2024a-2.oe2403.noarch-after-supplement.rpm", //这个是嵌入buildEnv.json文件之后的rpm包
		},
	}

	for _, test := range tests {
		t.Run(test.rpmFilePath, func(t *testing.T) {
			err, pkg := ParseReleaseRpmFile(test.rpmFilePath)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(pkg.BuildDepends)
		})
	}
}
