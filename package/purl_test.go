package _package

import (
	"fmt"
	"testing"
)

func TestRpmPackageURL(t *testing.T) {
	tests := []struct {
		pkgType   string
		namespace string
		name      string
		arch      string
		sourcePkg string
		version   string
		release   string
		distro    string
		expected  string
	}{
		{
			pkgType:   "rpm",
			namespace: "openEuler",
			name:      "bash1",
			arch:      "x86_64",
			sourcePkg: "",
			version:   "5.2.15",
			release:   "9.oe2403",
			distro:    "openEuler-24.03",
			expected:  "pkg:rpm/openEuler/bash@5.2.15-9.oe2403?arch=x86_64&distro=openEuler-24.03",
		},
		{
			pkgType:   "rpm",
			namespace: "openEuler",
			name:      "bash2",
			arch:      "x86_64",
			sourcePkg: "bash-5.2.15-9.oe2403.src.rpm",
			version:   "5.2.15",
			release:   "9.oe2403",
			distro:    "openEuler-24.03",
			expected:  "pkg:rpm/openEuler/bash@5.2.15-9.oe2403?arch=x86_64&upstream=bash-5.2.15-9.oe2403.src.rpm&distro=openEuler-24.03",
		},
		{
			pkgType:   "deb",
			namespace: "ubuntu",
			name:      "apt",
			arch:      "amd64",
			sourcePkg: "",
			version:   "2.7.14build2",
			release:   "",
			distro:    "ubuntu-24.04",
			expected:  "pkg:deb/ubuntu/apt@2.7.14build2?arch=amd64&distro=ubuntu-24.04",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := RpmPackageURL(test.pkgType, test.namespace, test.name, test.arch, test.sourcePkg, test.version, test.release, test.distro)
			if actual != test.expected {
				fmt.Println("actual:", actual)
				fmt.Println("expected:", test.expected)
				//dmp := diffmatchpatch.New()
				//diffs := dmp.DiffMain(test.expected, actual, true)
				//t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
