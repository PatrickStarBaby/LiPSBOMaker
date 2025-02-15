package source

import (
	"fmt"
	"testing"
)

func TestFetchDebBuildDep(t *testing.T) {
	tests := []struct {
		dscFilePath string
	}{
		{
			dscFilePath: "./test-fixtures/debPkg/apt-2.7.14build2/apt_2.7.14build2.dsc",
		},
	}

	for _, test := range tests {
		t.Run(test.dscFilePath, func(t *testing.T) {
			err, env := FetchDebBuildDep(test.dscFilePath)
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(env)
		})
	}
}
