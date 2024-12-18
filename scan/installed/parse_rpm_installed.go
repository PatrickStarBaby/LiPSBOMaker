package installed

import (
	"fmt"
	"github.com/package-url/packageurl-go"
	_package "slp/package"
	scan_utils "slp/utils"
	"strings"
)

func ParseInstalledRpm(pkgName string) (error, *_package.Pkg) {
	requires, err := GetRpmRequires(pkgName)
	if err != nil {
		fmt.Println(err)
	}
	for _, require := range requires {
		pkg, err := GetInstalledRpmInfo(require.Name)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(pkg.Metadata.Name)
		fmt.Println(pkg.Metadata.Description)
		fmt.Println("-------------")
	}
	return nil, nil
}

func GetRpmRequires(pkgName string) ([]scan_utils.RPM_NEVRA, error) {
	res, err := scan_utils.RunCommand("dnf", "repoquery", "--requires", "--resolve", "--installed", pkgName)
	if err != nil {
		return nil, fmt.Errorf("dnf repoquery --requires --resolve命令执行失败：%v", err)
	}
	pkgs := strings.Split(res, "\n")
	var requirePkgs []scan_utils.RPM_NEVRA
	for _, line := range pkgs {
		trimmedLine := strings.TrimSpace(line) // 去掉每行首尾空白
		if trimmedLine != "" {                 // 过滤空白行
			pkg, err := scan_utils.SplitRPMName(trimmedLine)
			if err != nil {
				fmt.Println(err)
				continue
			}
			fmt.Println("-------------")
			fmt.Println(pkg)
			if pkg.Name != pkgName { //出现自身依赖的要去掉，例如bash
				requirePkgs = append(requirePkgs, *pkg)
			}
		}
	}
	return requirePkgs, nil
}

func GetInstalledRpmInfo(pkgName string) (*_package.Pkg, error) {
	res, err := scan_utils.RunCommand("rpm", "-qi", pkgName)
	if err != nil {
		return nil, fmt.Errorf("rpm -qi命令执行失败：%v", err)
	}
	pkgInfo := make(map[string]string)
	lines := strings.Split(res, "\n")
	for _, line := range lines {
		if len(line) == 0 || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		pkgInfo[key] = value
	}

	metadata := _package.Metadata{}
	metadata.Lifecycle = _package.InstalledLifecycle
	metadata.Name = pkgInfo["Name"]
	metadata.Version = pkgInfo["Version"]
	metadata.Release = pkgInfo["Release"]
	metadata.Architecture = pkgInfo["Architecture"]
	metadata.Packager = pkgInfo["Packager"]
	metadata.Url = pkgInfo["URL"]
	metadata.Description = pkgInfo["Description"]
	metadata.SourcePkg = pkgInfo["Source RPM"]
	metadata.BuildHost = pkgInfo["Build Host"]
	metadata.BuildTime = pkgInfo["Build Date"]
	metadata.License = []string{pkgInfo["License"]}

	purl := _package.RpmPackageURL(packageurl.TypeDebian, "openEuler", pkgInfo["Name"], pkgInfo["Architecture"], metadata.SourcePkg, pkgInfo["Version"], pkgInfo["Release"], "openEuler-24.03")
	fmt.Println("PURL: ", purl)

	return &_package.Pkg{
		Metadata: &metadata,
	}, nil
}
