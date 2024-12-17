package installed

import (
	"fmt"
	_package "slp/package"
	scan_utils "slp/utils"
	"strings"
)

func ParseInstalledRpm(pkgName string) (error, *_package.Pkg) {
	GetInstalledRpmInfo(pkgName)
	return nil, nil
}

func GetInstalledRpmInfo(pkgName string) {
	res, err := scan_utils.RunCommand("dnf", "repoquery", "--requires", "--resolve", "--installed", pkgName)
	if err != nil {
		fmt.Println("dnf repoquery --requires --resolve命令执行失败：", err)
		return
	}
	pkgs := strings.Split(res, "\n")
	var requirePkgs []scan_utils.RPM_NEVRA
	for _, line := range pkgs {
		trimmedLine := strings.TrimSpace(line) // 去掉每行首尾空白
		if trimmedLine != "" {                 // 过滤空白行
			pkg, err := scan_utils.SplitRPMName(trimmedLine)
			if err != nil {
				continue
			}
			fmt.Println(pkg.Name)
			if pkg.Name != pkgName { //出现自身依赖的要去掉，例如bash
				requirePkgs = append(requirePkgs, *pkg)
			}
		}
	}
}
