package installed

import (
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	_package "slp/package"
	scan_utils "slp/utils"
	"strings"
	"time"
)

func ParseInstalledRpm(pkgName string) (error, *_package.Pkg) {
	requires, err := GetRpmRequires(pkgName)
	if err != nil {
		fmt.Println(err)
	}
	pkg := _package.Pkg{}
	metadata, err := GetInstalledRpmInfo(pkgName)
	if err != nil {
		fmt.Println(err)
	}
	pkg.Metadata = metadata
	var deps []_package.Depend
	dependencyBomref := []string{}
	for _, require := range requires {
		p, err := GetInstalledRpmInfo(require.Name)
		if err != nil {
			fmt.Println(err)
		}
		dep := _package.Depend{}
		dep.Metadata = *p
		deps = append(deps, dep)
		dependencyBomref = append(dependencyBomref, dep.BomRef)
		fmt.Println(dep.Name)
		fmt.Println(dep.Description)
		fmt.Println(dep.BomRef)
		fmt.Println("-------------")
	}
	pkg.Depends = &deps

	directDependency := cyclonedx.Dependency{
		Ref:          pkg.Metadata.BomRef,
		Dependencies: &dependencyBomref,
	}
	pkg.Dependencies = &[]cyclonedx.Dependency{directDependency}
	return nil, &pkg
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

func GetInstalledRpmInfo(pkgName string) (*_package.Metadata, error) {
	res, err := scan_utils.RunCommand("rpm", "-qi", pkgName)
	if err != nil {
		return nil, fmt.Errorf("rpm -qi命令执行失败：%v", err)
	}
	pkgInfo := make(map[string]string)
	lines := strings.Split(res, "\n")
	for i := 0; i < len(lines); i++ {
		parts := strings.SplitN(lines[i], ":", 2)
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "Description" {
			i++
			for ; i < len(lines); i++ {
				value = value + "\n" + lines[i]
			}
		}
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
	metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", metadata.Name, metadata.Version)
	metadata.Description = pkgInfo["Description"]
	metadata.SourcePkg = pkgInfo["Source RPM"]
	metadata.BuildHost = pkgInfo["Build Host"]
	metadata.BuildTime = pkgInfo["Build Date"]
	if pkgInfo["License"] != "" {
		metadata.License = []string{pkgInfo["License"]}
	}

	// namespace: "openEuler"; distro: "openEuler-24.03"
	purl := _package.RpmPackageURL(packageurl.TypeDebian, "", pkgInfo["Name"], pkgInfo["Architecture"], metadata.SourcePkg, pkgInfo["Version"], pkgInfo["Release"], "")
	fmt.Println("PURL: ", purl)
	metadata.PURL = purl

	bomRef, err := _package.GetBomRef(purl, struct {
		Name      string
		Version   string
		Release   string
		Arch      string
		timestamp time.Time //加上时间戳防止重复
	}{
		Name:      metadata.Name,
		Version:   metadata.Version,
		Release:   metadata.Release,
		Arch:      metadata.Architecture,
		timestamp: time.Now(),
	}, "package-id")
	fmt.Println("BOMRef: ", bomRef)
	metadata.BomRef = bomRef

	return &metadata, nil
}
