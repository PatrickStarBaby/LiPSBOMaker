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
			patchesDirPath: "E:\\postgraduate\\SBOM调研\\Rpm\\sourcePackages\\bash-5.2.21\\debian\\patches",
		},
		{
			patchesDirPath: "E:\\postgraduate\\SBOM调研\\Rpm\\sourcePackages\\apt-2.7.14build2",
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
			rootPath: "E:\\postgraduate\\SBOM调研\\Rpm\\sourcePackages\\apt_2.7.14build2.dsc",
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
			rootPath: "E:\\postgraduate\\SBOM调研\\Rpm&Deb\\工具\\slp\\sourcefile\\ubuntu24.04.1 LTS-source\\apt\\apt_2.7.14build2.dsc",
		},
		{
			rootPath: "E:\\postgraduate\\SBOM调研\\Rpm&Deb\\工具\\slp\\sourcefile\\ubuntu24.04.1 LTS-source\\bash\\bash_5.2.21-2ubuntu4.dsc",
		},
	}

	for _, test := range tests {
		t.Run(test.rootPath, func(t *testing.T) {
			readDscFileByPault(test.rootPath)
		})
	}
}
