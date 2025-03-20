package release

import (
	"encoding/json"
	"fmt"
	"os"
	_package "slp/package"
	"slp/scan/source"
	scan_utils "slp/utils"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/sassoftware/go-rpmutils"
)

func ParseReleaseRpmFile(rpmPath string) (error, *_package.Pkg) {
	file, err := os.Open(rpmPath)
	if err != nil {
		return fmt.Errorf("failed to open RPM file: %v", err), nil
	}
	defer file.Close()
	rpm, err := rpmutils.ReadRpm(file)
	if err != nil {
		return fmt.Errorf("failed to read RPM file: %v", err), nil
	}

	// Getting metadata
	nevra, err := rpm.Header.GetNEVRA()
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the nevra:%v", err))
	}

	//-------OS-------
	os, err := rpm.Header.GetStrings(rpmutils.OS)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the OS:%v", err))
	}
	fmt.Println("OS: ", os)

	//-------sourceRPM-------
	sourceRPM, err := rpm.Header.GetStrings(rpmutils.SOURCERPM)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the sourceRPM:%v", err))
	}
	fmt.Println("Source RPM: ", sourceRPM)

	//-------buildHost-------
	buildHost, err := rpm.Header.GetStrings(rpmutils.BUILDHOST)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the buildHost:%v", err))
	}
	fmt.Println("buildHost: ", buildHost)

	//-------buildTime-------
	buildTime, err := rpm.Header.GetUint32s(rpmutils.BUILDTIME)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the buildTime:%v", err))
	}
	buildDate := time.Unix(int64(buildTime[0]), 0)
	fmt.Println("buildTime: ", buildDate)

	// PURL
	// namespace: "openEuler"; distro: "openEuler-24.03"
	purl := _package.RpmPackageURL(packageurl.TypeRPM, "", nevra.Name, nevra.Arch, sourceRPM[0], nevra.Version, nevra.Release, "")
	fmt.Println("PURL: ", purl)

	// BOMRef
	bomRef, err := _package.GetBomRef(purl, struct {
		Name      string
		Version   string
		Release   string
		Arch      string
		BuildTime time.Time
		timestamp time.Time //加上时间戳防止重复
	}{
		Name:      nevra.Name,
		Version:   nevra.Version,
		Release:   nevra.Release,
		Arch:      nevra.Arch,
		BuildTime: buildDate,
		timestamp: time.Now(),
	}, "package-id")
	fmt.Println("BOMRef: ", bomRef)

	//-------licenses-------
	licenses, err := rpm.Header.GetStrings(rpmutils.LICENSE)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the licenses:%v", err))
	}
	fmt.Println("licenses: ", licenses)

	//-------url-------
	url, err := rpm.Header.GetStrings(rpmutils.URL)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the url:%v", err))
	}
	fmt.Println("url: ", url)

	//-------rpmVersion-------
	rpmVersion, err := rpm.Header.GetStrings(rpmutils.RPMVERSION)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the rpmVersion:%v", err))
	}
	fmt.Println("rpmVersion: ", rpmVersion)

	//-------description-------
	description, err := rpm.Header.GetStrings(rpmutils.DESCRIPTION)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the description:%v", err))
	}
	fmt.Println("description: ", description)

	//-------packager-------
	packager, err := rpm.Header.GetStrings(rpmutils.PACKAGER)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the packager:%v", err))
	}
	fmt.Println("packager: ", packager)

	//-------provides,提供的二进制包-------
	provides, err := rpm.Header.GetStrings(rpmutils.PROVIDENAME)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the provides:%v", err))
	}
	//-------provideVersion-------
	provideVersion, err := rpm.Header.GetStrings(rpmutils.PROVIDEVERSION)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the provideVersion:%v", err))
	}
	//-------provideFlags，获取版本符号（>=，<=等）-------
	provideFlags, err := rpm.Header.GetUint32s(rpmutils.PROVIDEFLAGS)
	packageList := []string{}
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the provideFlags:%v", err))
	}
	if len(provides) == len(provideVersion) && len(provideVersion) == len(provideFlags) {
		// 将可以打出的软件包名称和版本对应起来并输出
		fmt.Println("The provided package name and version:")
		for i := 0; i < len(provides); i++ {
			packageList = append(packageList, provides[i]+scan_utils.GetOperator(provideFlags[i])+provideVersion[i])
			fmt.Printf("Name: %s, Version: %s %s\n", provides[i], scan_utils.GetOperator(provideFlags[i]), provideVersion[i])
		}
	} else {
		fmt.Println("The provided package name, version, and symbol count are inconsistent.")
	}

	// ------------ 给pkg赋值 ------------
	metadata := _package.Metadata{}
	metadata.Lifecycle = _package.ReleaseLifecycle
	metadata.BomRef = bomRef
	metadata.Name = nevra.Name
	metadata.Version = nevra.Version
	metadata.Release = nevra.Release
	metadata.Architecture = nevra.Arch
	metadata.PURL = purl
	metadata.Url = url[0]
	metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", metadata.Name, metadata.Version)
	metadata.Description = description[0]
	metadata.License = licenses
	metadata.PackageList = strings.Join(packageList, ", ")

	metadata.SourcePkg = strings.Join(sourceRPM, ", ")
	if len(packager) > 0 {
		metadata.Packager = packager[0]
	}
	metadata.BuildTime = buildDate.String()
	metadata.BuildHost = strings.Join(buildHost, ", ")

	//-------require-------
	depends := []_package.Depend{}
	dependencyBomref := []string{}
	require, err := rpm.Header.GetStrings(rpmutils.REQUIRENAME)
	//require = removeItemFromSlice(require, "rpmlib(CompressedFileNames)")
	//require = removeItemFromSlice(require, "rpmlib(FileDigests)")
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the require:%v", err))
	}

	//-------requireFlags，获取版本符号（>=，<=等）-------
	requireFlags, err := rpm.Header.GetUint32s(rpmutils.REQUIREFLAGS)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the requireFlags:%v", err))
	}
	//-------requireVersion-------
	requireVersion, err := rpm.Header.GetStrings(rpmutils.REQUIREVERSION)
	if err != nil {
		fmt.Println(fmt.Errorf("An error occurred while reading the requireVersion:%v", err))
	}
	if len(require) == len(requireVersion) && len(requireVersion) == len(requireFlags) {
		// 将依赖名称和版本对应起来并输出
		fmt.Println("Require Name and Version:")
		versions := []string{}
		//拼接得到版本列表
		for i := 0; i < len(require); i++ {
			version := scan_utils.GetOperator(requireFlags[i]) + requireVersion[i]
			versions = append(versions, version)
			fmt.Printf("Require: %s, Version: %s\n", require[i], version)
		}
		//注意要去重
		uniqueNames, uniqueVersions := removeDuplicates(require, versions)
		for i := 0; i < len(uniqueNames); i++ {
			dependBomRef, _ := _package.GetBomRef("Require:"+uniqueNames[i], struct {
				Name      string
				Version   string
				timestamp time.Time //加上时间戳防止重复
			}{
				Name:      uniqueNames[i],
				Version:   uniqueVersions[i],
				timestamp: time.Now(),
			}, "package-id")
			depends = append(depends, _package.Depend{
				Metadata: _package.Metadata{
					Name:    uniqueNames[i],
					Version: uniqueVersions[i],
					BomRef:  dependBomRef,
				},
			})
			dependencyBomref = append(dependencyBomref, dependBomRef)
			fmt.Printf("Require: %s, Version: %s\n", uniqueNames[i], uniqueVersions[i])
		}
	} else {
		fmt.Println("The require name, version, size, and symbol count are inconsistent.")
	}

	directDependency := cyclonedx.Dependency{
		Ref:          bomRef,
		Dependencies: &dependencyBomref,
	}

	// 从rpm包中提取文件
	reader, err := rpm.PayloadReader()
	if err != nil {
		fmt.Println(fmt.Errorf("rpm.PayloadReader() error:%v", err))
	}
	var buildDp []_package.BuildDepend
	// 使用 reader 读取 RPM 包中的文件
	for {
		header, err := reader.Next()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			fmt.Println(fmt.Errorf("An error occurred while using the reader to read files from the RPM package:%v", err))
		}
		// 从 buildEnv.json 文件中提取构建依赖精确补充信息
		if strings.HasSuffix(header.Filename(), "buildEnv.json") {
			var buildEnv source.RpmBuildEnv
			// 读取文件内容
			decoder := json.NewDecoder(reader)
			err = decoder.Decode(&buildEnv)
			if err != nil {
				fmt.Println(fmt.Errorf("An error occurred while serializing the buildEnv.json file:%v", err))
			}

			for _, providers := range buildEnv.BuildRequires {
				for _, provider := range providers.Provider {
					existSameProvider, index := ifExistSameProvider(buildDp, provider)
					//判断多个功能是否同属于一个Provider，同属一个Provider时不需要新增Depend，只需修改RpmRequire字段
					if existSameProvider {
						buildDp[index].RpmRequire = buildDp[index].RpmRequire + ", " + providers.RequireProvide
					} else {
						buildDp = append(buildDp, _package.BuildDepend{
							Metadata:   *provider.Metadata,
							RpmRequire: providers.RequireProvide,
						})
					}
				}
			}
		}
	}

	return nil, &_package.Pkg{
		Metadata:     &metadata,
		Depends:      &depends,
		BuildDepends: &buildDp,
		Dependencies: &[]cyclonedx.Dependency{directDependency},
	}
}

func ifExistSameProvider(deps []_package.BuildDepend, toBeJudge _package.Pkg) (exist bool, index int) {
	exist = false
	for i := 0; i < len(deps); i++ {
		if toBeJudge.Metadata.Name == deps[i].Name {
			exist = true
			index = i
		}
	}
	return exist, index
}

func removeDuplicates(names []string, versions []string) ([]string, []string) {
	if len(names) != len(versions) {
		panic("names and versions must be of the same length")
	}

	seen := make(map[string]bool)
	var uniqueNames []string
	var uniqueVersions []string

	for i := range names {
		pair := names[i] + ":" + versions[i]
		if !seen[pair] {
			seen[pair] = true
			uniqueNames = append(uniqueNames, names[i])
			uniqueVersions = append(uniqueVersions, versions[i])
		}
	}

	return uniqueNames, uniqueVersions
}
