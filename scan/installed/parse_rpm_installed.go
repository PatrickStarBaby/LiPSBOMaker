package installed

import (
	"fmt"
	_package "slp/package"
	scan_utils "slp/utils"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
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
	for _, requireList := range requires {
		for _, require := range requireList {
			existSameProvider, index := ifExistSameProvider(deps, require)
			//判断多个功能是否同属于一个Provider，同属一个Provider时不需要新增Depend，只需修改RpmRequire字段
			if existSameProvider {
				deps[index].RpmRequire = deps[index].RpmRequire + ", " + require.RpmRequire
			} else {
				deps = append(deps, require)
				dependencyBomref = append(dependencyBomref, require.BomRef)
			}
		}
	}
	pkg.Depends = &deps

	directDependency := cyclonedx.Dependency{
		Ref:          pkg.Metadata.BomRef,
		Dependencies: &dependencyBomref,
	}
	pkg.Dependencies = &[]cyclonedx.Dependency{directDependency}
	return nil, &pkg
}

func ifExistSameProvider(deps []_package.Depend, toBeJudge _package.Depend) (exist bool, index int) {
	exist = false
	for i := 0; i < len(deps); i++ {
		if toBeJudge.Name == deps[i].Name {
			exist = true
			index = i
		}
	}
	return exist, index
}

// 三个获取依赖的命令：rpm -qR xxx  /  dnf deplist xxx  /  dnf repoquery --requires --resolve --installed xxx
// 然后用rpm -q --whatprovides 找到Provider
func GetRpmRequires(pkgName string) ([][]_package.Depend, error) {
	res, err := scan_utils.RunCommand("rpm", "-qR", pkgName)
	if err != nil {
		fmt.Println(res)
		return nil, fmt.Errorf("The 'rpm -qR' command execution failed.%v", err)
	}
	pkgs := strings.Split(res, "\n")
	pkgs = scan_utils.RemoveDuplicates(pkgs)
	var requirePkgs [][]_package.Depend
	for _, line := range pkgs {
		trimmedLine := strings.Split(strings.TrimSpace(line), " ")[0] // 去掉每行首尾空白, 并且提取出name
		if trimmedLine != "" {                                        // 过滤空白行
			metadataList, err := getProvider(trimmedLine)
			if err != nil {
				// fmt.Println(err)
				//continue
			}
			var temp []_package.Depend
			for _, metadata := range metadataList {
				if metadata.Name != pkgName { //出现自身依赖的要去掉，例如bash
					temp = append(temp, _package.Depend{
						Metadata:   metadata,
						RpmRequire: trimmedLine,
					})
				}
			}
			requirePkgs = append(requirePkgs, temp)
		}
	}
	return requirePkgs, nil
}

func getProvider(provide string) ([]_package.Metadata, error) {
	res, err := scan_utils.RunCommand("rpm", "-q", "--whatprovides", provide)
	if err != nil {
		fmt.Println(res)
		return nil, fmt.Errorf("The 'rpm -q --whatprovides' command execution:")
	}
	lines := strings.Split(res, "\n")
	var providerList []_package.Metadata
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			provider, err := GetInstalledRpmInfo(trimmedLine)
			if err != nil {
				fmt.Println(err)
				continue
			}
			providerList = append(providerList, *provider)
		}
	}
	return providerList, nil
}

func GetInstalledRpmInfo(pkgName string) (*_package.Metadata, error) {
	res, err := scan_utils.RunCommand("rpm", "-qi", pkgName)
	if err != nil {
		return nil, fmt.Errorf("The 'rpm -qi' command execution:%v", err)
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
	sourcePkgNEVRA, err := scan_utils.SplitRPMNameWithoutEpoch(pkgInfo["Source RPM"])
	if err != nil {
		metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", metadata.Name, metadata.Version)
	} else {
		metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", sourcePkgNEVRA.Name, sourcePkgNEVRA.Version)
	}

	metadata.Description = pkgInfo["Description"]
	metadata.SourcePkg = pkgInfo["Source RPM"]
	metadata.BuildHost = pkgInfo["Build Host"]
	metadata.BuildTime = pkgInfo["Build Date"]
	if pkgInfo["License"] != "" {
		metadata.License = []string{pkgInfo["License"]}
	}

	// namespace: "openEuler"; distro: "openEuler-24.03"
	namespace, distro := getOsInfo()
	purl := _package.RpmPackageURL(packageurl.TypeRPM, namespace, pkgInfo["Name"], pkgInfo["Architecture"], metadata.SourcePkg, pkgInfo["Version"], pkgInfo["Release"], distro)
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
