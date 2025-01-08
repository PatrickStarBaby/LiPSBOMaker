package installed

import (
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	_package "slp/package"
	"slp/utils"
	"strings"
	"time"
)

func ParseInstalledDeb(pkgName string) (error, *_package.Pkg) {
	info, err := GetInstalledDebInfo(pkgName)
	if err != nil {
		return err, nil
	}
	// 获取到三种运行依赖的包名列表
	preDepNames, depNames, builtUsingNames := getDeps(info)

	metaData, err := GetMetaData(pkgName)
	if err != nil {
		return err, nil
	}

	var deps []_package.Depend
	dependencyBomref := []string{}
	for _, depName := range depNames {
		p, err := GetMetaData(depName)
		if err != nil {
			fmt.Println(err)
		}
		deps = append(deps, _package.Depend{
			Metadata:      *p,
			DebDependType: "Depends",
		})
		dependencyBomref = append(dependencyBomref, p.BomRef)
	}
	for _, preDepName := range preDepNames {
		p, err := GetMetaData(preDepName)
		if err != nil {
			fmt.Println(err)
		}
		deps = append(deps, _package.Depend{
			Metadata:      *p,
			DebDependType: "Pre-Depends",
		})
		dependencyBomref = append(dependencyBomref, p.BomRef)
	}
	for _, builtUsingName := range builtUsingNames {
		p, err := GetMetaData(builtUsingName)
		if err != nil {
			fmt.Println(err)
		}
		deps = append(deps, _package.Depend{
			Metadata:      *p,
			DebDependType: "Built-Using",
		})
		dependencyBomref = append(dependencyBomref, p.BomRef)
	}
	directDependency := cyclonedx.Dependency{
		Ref:          metaData.BomRef,
		Dependencies: &dependencyBomref,
	}
	return nil, &_package.Pkg{
		Metadata:     metaData,
		Depends:      &deps,
		Dependencies: &[]cyclonedx.Dependency{directDependency},
	}
}

func GetMetaData(pkgName string) (*_package.Metadata, error) {
	info, err := GetInstalledDebInfo(pkgName)
	if err != nil {
		return nil, err
	}
	metadata := _package.Metadata{}
	metadata.Lifecycle = _package.InstalledLifecycle
	metadata.Name = info["Package"]
	metadata.Version = info["Version"]
	metadata.Architecture = info["Architecture"]
	metadata.Url = info["Homepage"]
	metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", metadata.Name, metadata.Version)
	metadata.Description = info["Description"]
	metadata.Maintainer = info["Maintainer"]
	metadata.OriginalMaintainer = info["Original-Maintainer"]
	metadata.Section = info["Section"]
	metadata.Priority = info["Priority"]
	//判断上游源码包
	value, exists := info["Source"]
	if exists {
		metadata.SourcePkg = value
	} else {
		metadata.SourcePkg = info["Package"]
	}
	// PURL
	namespace, distro := getOsInfo()
	// namespace: "ubuntu"; distro: "ubuntu-24.04"
	purl := _package.RpmPackageURL(packageurl.TypeDebian, namespace, info["Package"], info["Architecture"], metadata.SourcePkg, info["Version"], "", distro)
	fmt.Println("PURL: ", purl)
	metadata.PURL = purl
	// BOMRef
	bomRef, err := _package.GetBomRef(purl, struct {
		Name         string
		Version      string
		Architecture string
		timestamp    time.Time //加上时间戳防止重复
	}{
		Name:         info["Package"],
		Version:      info["Version"],
		Architecture: info["Architecture"],
		timestamp:    time.Now(),
	}, "package-id")
	fmt.Println("BOMRef: ", bomRef)
	metadata.BomRef = bomRef

	return &metadata, nil
}

func GetInstalledDebInfo(pkgName string) (map[string]string, error) {
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

	for key, value := range pkgInfo {
		fmt.Printf("Key: %s, Value: %s\n", key, value)
	}

	return pkgInfo, nil
}

func getDeps(pkgInfo map[string]string) (preDeps, deps, builtUsing []string) {
	_, exists := pkgInfo["Pre-Depends"]
	if exists {
		fields := strings.Split(pkgInfo["Pre-Depends"], ",")
		for _, field := range fields {
			preDeps = append(preDeps, splitPackageChoice(field)...)
		}
		fmt.Println(preDeps)
	}

	_, exists = pkgInfo["Depends"]
	if exists {
		fields := strings.Split(pkgInfo["Depends"], ",")
		for _, field := range fields {
			deps = append(deps, splitPackageChoice(field)...)
		}
		fmt.Println(deps)
	}

	_, exists = pkgInfo["Built-Using"]
	if exists {
		fields := strings.Split(pkgInfo["Built-Using"], ",")
		for _, field := range fields {
			builtUsing = append(builtUsing, splitPackageChoice(field)...)
		}
		fmt.Println(builtUsing)
	}

	return
}

// 将 default-mta (>= 2:6.2.1+dfsg1) | mail-transport-agent 提取出 default-mta、mail-transport-agent
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

// 获取软件包所处的系统信息以生成PURL
func getOsInfo() (namespace, distro string) {
	res, err := scan_utils.RunCommand("cat", "/etc/os-release")
	if err != nil {
		fmt.Println(fmt.Errorf("dpkg -s命令执行失败：%v", err))
		return "", ""
	}

	osInfo := make(map[string]string)
	var currentKey string
	lines := strings.Split(res, "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		// Check if line is a new field
		if strings.HasPrefix(line, "VERSION_ID") || strings.HasPrefix(line, "ID") {
			// Split the line by the first occurrence of ':'
			parts := strings.SplitN(line, "=", 2)
			currentKey = strings.TrimSpace(parts[0])
			temp := strings.TrimSpace(parts[1])
			osInfo[currentKey] = strings.Trim(temp, "\"")
		}

	}
	return osInfo["ID"], osInfo["ID"] + "-" + osInfo["VERSION_ID"]
}
