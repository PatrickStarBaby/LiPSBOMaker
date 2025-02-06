package scan_utils

import (
	"fmt"
	"github.com/sassoftware/go-rpmutils"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// 转换版本符号（>=，<=等）
func GetOperator(flag uint32) string {
	switch {
	case flag&rpmutils.RPMSENSE_LESS != 0 && flag&rpmutils.RPMSENSE_EQUAL != 0:
		return "<="
	case flag&rpmutils.RPMSENSE_GREATER != 0 && flag&rpmutils.RPMSENSE_EQUAL != 0:
		return ">="
	case flag&rpmutils.RPMSENSE_LESS != 0:
		return "<"
	case flag&rpmutils.RPMSENSE_GREATER != 0:
		return ">"
	case flag&rpmutils.RPMSENSE_EQUAL != 0:
		return "="
	default:
		return ""
	}
}

// 判断路径是否存在
func PathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// MatchNamedCaptureGroups takes a regular expression and string and returns all of the named capture group results in a map.
// This is only for the first match in the regex. Callers shouldn't be providing regexes with multiple capture groups with the same name.
func MatchNamedCaptureGroup(regEx *regexp.Regexp, content string) map[string]string {
	// note: we are looking across all matches and stopping on the first non-empty match. Why? Take the following example:
	// input: "cool something to match against" pattern: `((?P<name>match) (?P<version>against))?`. Since the pattern is
	// encapsulated in an optional capture group, there will be results for each character, but the results will match
	// on nothing. The only "true" match will be at the end ("match against").
	allMatches := regEx.FindAllStringSubmatch(content, -1)
	var results map[string]string
	for _, match := range allMatches {
		// fill a candidate results map with named capture group results, accepting empty values, but not groups with
		// no names
		for nameIdx, name := range regEx.SubexpNames() {
			if nameIdx > len(match) || len(name) == 0 {
				continue
			}
			if results == nil {
				results = make(map[string]string)
			}
			results[name] = match[nameIdx]
		}
		// note: since we are looking for the first best potential match we should stop when we find the first one
		// with non-empty results.
		if !isEmptyMap(results) {
			break
		}
	}
	return results
}

func isEmptyMap(m map[string]string) bool {
	if len(m) == 0 {
		return true
	}
	for _, value := range m {
		if value != "" {
			return false
		}
	}
	return true
}

// 执行命令并返回输出
func RunCommand(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	// 捕获标准输出
	output, err := cmd.CombinedOutput()

	if err != nil {
		// 包未安装的错误单独处理
		if strings.Contains(string(output), "is not installed") {
			return "NotInstalled", err
		}
		// 其他错误
		return string(output), err
	}
	return string(output), nil
}

// 检查系统中是否存在指定的命令
func CheckCommandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// RPM_NEVRA 结构体
type RPM_NEVRA struct {
	Name    string
	Epoch   string
	Version string
	Release string
	Arch    string
}

// SplitRPMFilename 解析 RPM 包名称
/*
	匹配正确的情况：
	不带后缀：
	glibc-0:2.38-47.oe2403.x86_64
	elfutils-default-yama-scope-0:0.190-3.oe2403.noarch
	带文件后缀：
	coreutils-0:9.4-3.oe2403.x86_64.rpm

	一些特殊的情况：
	gcc-c++-0:12.3.1-38.oe2403.x86_64
	libstdc++-0:12.3.1-38.oe2403.x86_64
	glibc-0:2.38-47.oe2403.x86_64
	elfutils-default-yama-scope-0:0.190-3.oe2403.noarch
*/
func SplitRPMName(rpmPkgName string) (*RPM_NEVRA, error) {
	// 定义正则表达式解析 RPM 名称
	pattern := `^(?P<Name>[\w\-\+]+)-(?P<Epoch>\d+):(?P<Version>[\d\.]+)-(?P<Release>[\w\.]+)\.(?P<Arch>[\w_]+)(\.rpm)?$`
	re := regexp.MustCompile(pattern)

	// 执行正则匹配
	match := re.FindStringSubmatch(rpmPkgName)
	if match == nil {
		return nil, fmt.Errorf("SplitRPMName无法解析 RPM 文件名: %s", rpmPkgName)
	}

	// 提取命名组
	result := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i > 0 && name != "" {
			result[name] = match[i]
		}
	}

	// 构建 NEVRA 结构体
	return &RPM_NEVRA{
		Name:    result["Name"],
		Epoch:   result["Epoch"],
		Version: result["Version"],
		Release: result["Release"],
		Arch:    result["Arch"],
	}, nil
}

func SplitRPMNameWithoutEpoch(rpmPkgName string) (*RPM_NEVRA, error) {
	// 定义正则表达式解析 RPM 名称
	pattern := `^(?P<Name>[\w\-\+]+)-(?P<Version>[\d\.]+)-(?P<Release>[\w\.]+)\.(?P<Arch>[\w_]+)(\.rpm)?$`
	re := regexp.MustCompile(pattern)

	// 执行正则匹配
	match := re.FindStringSubmatch(rpmPkgName)
	if match == nil {
		return nil, fmt.Errorf("SplitRPMNameWithoutEpoch无法解析 RPM 文件名: %s", rpmPkgName)
	}

	// 提取命名组
	result := make(map[string]string)
	for i, name := range re.SubexpNames() {
		if i > 0 && name != "" {
			result[name] = match[i]
		}
	}

	// 构建 NEVRA 结构体
	return &RPM_NEVRA{
		Name:    result["Name"],
		Epoch:   result["Epoch"],
		Version: result["Version"],
		Release: result["Release"],
		Arch:    result["Arch"],
	}, nil
}
