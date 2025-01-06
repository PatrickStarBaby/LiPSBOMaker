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
	fmt.Println("123")
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
	for key, value := range pkgInfo {
		fmt.Printf("Key: %s, Value: %s\n", key, value)
	}
	metadata := _package.Metadata{}

	return &metadata, nil
}
