package scan_utils

import (
	"bytes"
	"github.com/sassoftware/go-rpmutils"
	"os"
	"os/exec"
	"regexp"
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
	var out bytes.Buffer
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

// 检查系统中是否存在指定的命令
func CheckCommandExists(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}
