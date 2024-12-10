package source

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"slp/utils"
)

// For more information see: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/#license-syntax

var (
	licensePattern           = regexp.MustCompile(`^License: (?P<license>\S*)`)
	commonLicensePathPattern = regexp.MustCompile(`/usr/share/common-licenses/(?P<license>[0-9A-Za-z_.\-]+)`)
)

// 解析deb源文件中的Copyright文件
func parseLicensesFromCopyright(filePath string) ([]string, error) {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	findings := strset.New()

	for scanner.Scan() {
		line := scanner.Text()
		if value := findLicenseClause(licensePattern, "license", line); value != "" {
			findings.Add(value)
		}
		if value := findLicenseClause(commonLicensePathPattern, "license", line); value != "" {
			findings.Add(value)
		}
	}
	// 检查扫描错误
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading Copyright file: %w", err)
	}

	results := findings.List()

	sort.Strings(results)

	return results, nil
}

func findLicenseClause(pattern *regexp.Regexp, valueGroup, line string) string {
	matchesByGroup := scan_utils.MatchNamedCaptureGroup(pattern, line)

	candidate, ok := matchesByGroup[valueGroup]
	if !ok {
		return ""
	}

	return ensureIsSingleLicense(candidate)
}

func ensureIsSingleLicense(candidate string) (license string) {
	candidate = strings.TrimSpace(candidate)
	if strings.Contains(candidate, " or ") || strings.Contains(candidate, " and ") {
		// this is a multi-license summary, ignore this as other recurrent license lines should cover this
		return
	}
	if candidate != "" && strings.ToLower(candidate) != "none" {
		// the license may be at the end of a sentence, clean . characters
		license = strings.TrimSuffix(candidate, ".")
	}
	return license
}
