package installed

import (
	"fmt"
	_package "slp/package"
	"slp/utils"
	"strings"
)

func ParseInstalledDeb(pkgName string) (error, *_package.Pkg) {
	GetInstalledDebInfo(pkgName)
	return nil, nil
}

// installAptRdepends 安装 apt-rdepends
func installAptRdepends() error {
	fmt.Println("apt-rdepends 未安装，正在安装...")
	if _, err := scan_utils.RunCommand("sudo", "apt-get", "update"); err != nil {
		return fmt.Errorf("failed to update package lists: %v", err)
	}

	if _, err := scan_utils.RunCommand("sudo", "apt-get", "install", "-y", "apt-rdepends"); err != nil {
		return fmt.Errorf("failed to install apt-rdepends: %v", err)
	}
	return nil
}

func GetInstalledDebInfo(pkgName string) (*_package.Metadata, error) {
	res, err := scan_utils.RunCommand("dpkg", "-s", pkgName)
	if err != nil {
		return nil, fmt.Errorf("dpkg -s命令执行失败：%v", err)
	}

	pkgInfo := make(map[string]string)

	var currentKey string

	lines := strings.Split(res, "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		// Check if line is a new field
		if !strings.HasPrefix(line, " ") && strings.Contains(line, ":") {
			// Split the line by the first occurrence of ':'
			parts := strings.SplitN(line, ":", 2)
			currentKey = strings.TrimSpace(parts[0])
			pkgInfo[currentKey] = strings.TrimSpace(parts[1])
		} else if currentKey != "" {
			// If line starts with a space, it's a continuation of the previous field
			pkgInfo[currentKey] += " " + strings.TrimSpace(line)
		}

	}

	_, exists := pkgInfo["Pre-Depends"]
	if exists {
		fields := strings.Split(pkgInfo["Pre-Depends"], ",")
		var preDeps []string
		for _, field := range fields {
			preDeps = append(preDeps, splitPackageChoice(field)...)
		}
		fmt.Println(preDeps)
	}

	_, exists = pkgInfo["Depends"]
	if exists {
		fields := strings.Split(pkgInfo["Depends"], ",")
		var deps []string
		for _, field := range fields {
			deps = append(deps, splitPackageChoice(field)...)
		}
		fmt.Println(deps)
	}

	for key, value := range pkgInfo {
		fmt.Printf("Key: %s, Value: %s\n", key, value)
	}
	metadata := _package.Metadata{}

	return &metadata, nil
}

func splitPackageChoice(s string) (ret []string) {
	fields := strings.Split(s, "|")
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			ret = append(ret, stripVersionSpecifier(field))
		}
	}
	return ret
}

func stripVersionSpecifier(s string) string {
	// examples:
	// libgmp10 (>= 2:6.2.1+dfsg1)         -->  libgmp10
	// libgmp10                            -->  libgmp10
	// foo [i386]                          -->  foo
	// default-mta | mail-transport-agent  -->  default-mta | mail-transport-agent
	// kernel-headers-2.2.10 [!hurd-i386]  -->  kernel-headers-2.2.10

	return strings.TrimSpace(SplitAny(s, "[(<>=")[0])
}

func SplitAny(s string, seps string) []string {
	splitter := func(r rune) bool {
		return strings.ContainsRune(seps, r)
	}
	result := strings.FieldsFunc(s, splitter)
	if len(result) == 0 {
		return []string{s}
	}
	return result
}
