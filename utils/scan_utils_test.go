package scan_utils

import (
	"fmt"
	"testing"
)

func TestSplitRPMName(t *testing.T) {
	tests := []struct {
		rpmPkgName string
		expected   *RPM_NEVRA
	}{
		{
			rpmPkgName: "glibc-0:2.38-47.oe2403.x86_64",
			expected: &RPM_NEVRA{
				Name:    "glibc",
				Epoch:   "0",
				Version: "2.38",
				Release: "47.oe2403",
				Arch:    "x86_64",
			},
		},
		{
			rpmPkgName: "coreutils-0:9.4-3.oe2403.x86_64.rpm",
			expected: &RPM_NEVRA{
				Name:    "coreutils",
				Epoch:   "0",
				Version: "9.4",
				Release: "3.oe2403",
				Arch:    "x86_64",
			},
		},
		{
			rpmPkgName: "elfutils-default-yama-scope-0:0.190-3.oe2403.noarch",
			expected: &RPM_NEVRA{
				Name:    "elfutils-default-yama-scope",
				Epoch:   "0",
				Version: "0.190",
				Release: "3.oe2403",
				Arch:    "noarch",
			},
		},
		{
			rpmPkgName: "elfutils-default-yama-scope-0:0.190-3.oe2403.noarch.txt",
			expected:   nil,
		},
	}

	for _, test := range tests {
		t.Run(test.rpmPkgName, func(t *testing.T) {
			res, err := SplitRPMName(test.rpmPkgName)
			if err != nil {
				fmt.Println(err)
			}
			if res == test.expected {
				fmt.Println(res.Name, res.Version, res.Arch, res.Epoch, res.Release)
			} else {
				fmt.Println(res)
			}
		})
	}
}
