package release

import (
	"fmt"
	"testing"
)

func TestFetchDebBuildDep(t *testing.T) {
	tests := []struct {
		debFilePath string
	}{
		{
			debFilePath: "./test-fixtures/dpkg_1.22.6ubuntu6.1_amd64.deb", //解压后：control.tar.xz  data.tar.xz
		},
		{
			debFilePath: "./test-fixtures/python3_3.12.3-0ubuntu2_amd64.deb", //解压后：control.tar.zst  data.tar.zst
		},
		{
			debFilePath: "./test-fixtures/apt_2.7.14build2_amd64.deb", //这个是嵌入buildEnv.json文件之后的deb包
		},
	}

	for _, test := range tests {
		t.Run(test.debFilePath, func(t *testing.T) {
			/*err, pkg := ParseReleaseDebFile(test.debFilePath)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(pkg)*/

			err, pkg := ParseReleaseDebFile(test.debFilePath)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(pkg.BuildDepends)
		})
	}
}
