package source

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseLicensesFromCopyright(t *testing.T) {
	tests := []struct {
		fixture  string
		expected []string
	}{
		{
			fixture: "test-fixtures/copyright/libc6",
			// note: there are other licenses in this file that are not matched --we don't do full text license identification yet
			expected: []string{"GPL-2", "LGPL-2.1"},
		},
		{
			fixture:  "test-fixtures/copyright/trilicense",
			expected: []string{"GPL-2", "LGPL-2.1", "MPL-1.1"},
		},
		{
			fixture:  "test-fixtures/copyright/liblzma5",
			expected: []string{"Autoconf", "GPL-2", "GPL-2+", "GPL-3", "LGPL-2", "LGPL-2.1", "LGPL-2.1+", "PD", "PD-debian", "config-h", "noderivs", "permissive-fsf", "permissive-nowarranty", "probably-PD"},
		},
		{
			fixture:  "test-fixtures/copyright/libaudit-common",
			expected: []string{"GPL-1", "GPL-2", "LGPL-2.1"},
		},
		{
			fixture: "test-fixtures/copyright/python",
			// note: this should not capture #, Permission, This, see ... however it's not clear how to fix this (this is probably good enough)
			expected: []string{"#", "Apache", "Apache-2", "Apache-2.0", "Expat", "GPL-2", "ISC", "LGPL-2.1+", "PSF-2", "Permission", "Python", "This", "see"},
		},
		{
			fixture:  "test-fixtures/copyright/copyright-glibc-2.39",
			expected: []string{"GFDL-1.3", "GPL-2", "LGPL-2.1"},
		},
		{
			fixture:  "test-fixtures/copyright/copyright-apt-2.7.14build2",
			expected: []string{"BSD-3-clause", "Expat", "GPL-2", "GPL-2+"},
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			actual, _ := parseLicensesFromCopyright(test.fixture)
			t.Logf(strings.Join(actual, ","))
			if diff := cmp.Diff(test.expected, actual); diff != "" {
				t.Errorf("unexpected package licenses (-want +got):\n%s", diff)
			}
		})
	}
}
