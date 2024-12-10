package source

import (
	"fmt"
	"testing"
)

func TestParsePatchFiles(t *testing.T) {
	tests := []struct {
		patchesDirPath string
	}{
		{
			patchesDirPath: "test-fixtures/debPkg/bash_5.2.21/debian/patches",
		},
		{
			patchesDirPath: "test-fixtures/debPkg/apt-2.7.14build2",
		},
	}

	for _, test := range tests {
		t.Run(test.patchesDirPath, func(t *testing.T) {
			patchList, err := parsePatchFiles(test.patchesDirPath)
			if err != nil {
				fmt.Println(err)
			}
			// name, version, release, sourceURL, hash, license, maintainer := source.ParseSpecFile(specContent)
			for index, v := range patchList {
				fmt.Println(index, v)
			}
		})
	}
}

func TestReadDscFile(t *testing.T) {
	tests := []struct {
		rootPath string
		expected string
	}{
		{
			rootPath: "test-fixtures/debPkg/apt-2.7.14build2/apt_2.7.14build2.dsc",
			expected: "IsNative",
		},
	}

	for _, test := range tests {
		t.Run(test.rootPath, func(t *testing.T) {
			res, err := readDscFile(test.rootPath)
			if err != nil {
				fmt.Println(err)
			}

			for k, v := range res {
				fmt.Println(k, ",", v)
			}
		})
	}
}

func TestReadDscFileByPault(t *testing.T) {
	tests := []struct {
		rootPath string
		expected string
	}{
		{
			rootPath: "test-fixtures/debPkg/apt-2.7.14build2/apt_2.7.14build2.dsc",
		},
		{
			rootPath: "test-fixtures/debPkg/bash_5.2.21/bash_5.2.21-2ubuntu4.dsc",
		},
		{
			rootPath: "test-fixtures/debPkg/python3-defaults-3.12.3/python3-defaults_3.12.3-0ubuntu2.dsc",
		},
	}

	for _, test := range tests {
		t.Run(test.rootPath, func(t *testing.T) {
			readDscFileByPault(test.rootPath)
		})
	}
}
