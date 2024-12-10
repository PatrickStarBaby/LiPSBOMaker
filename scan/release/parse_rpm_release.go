package release

import (
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/sassoftware/go-rpmutils"
	"os"
	_package "slp/package"
	"slp/utils"
	"strings"
	"time"
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
		fmt.Println(fmt.Errorf("读取nevra时报错：%v", err))
	}

	//-------OS-------
	os, err := rpm.Header.GetStrings(rpmutils.OS)
	if err != nil {
		fmt.Println(fmt.Errorf("读取OS时报错：%v", err))
	}
	fmt.Println("OS: ", os)

	//-------sourceRPM-------
	sourceRPM, err := rpm.Header.GetStrings(rpmutils.SOURCERPM)
	if err != nil {
		fmt.Println(fmt.Errorf("读取sourceRPM时报错：%v", err))
	}
	fmt.Println("Source RPM: ", sourceRPM)

	//-------buildHost-------
	buildHost, err := rpm.Header.GetStrings(rpmutils.BUILDHOST)
	if err != nil {
		fmt.Println(fmt.Errorf("读取buildHost时报错：%v", err))
	}
	fmt.Println("buildHost: ", buildHost)

	//-------buildTime-------
	buildTime, err := rpm.Header.GetUint32s(rpmutils.BUILDTIME)
	if err != nil {
		fmt.Println(fmt.Errorf("读取buildTime时报错：%v", err))
	}
	buildDate := time.Unix(int64(buildTime[0]), 0)
	fmt.Println("buildTime: ", buildDate)

	// PURL
	purl := _package.RpmPackageURL(packageurl.TypeRPM, "openEuler", nevra.Name, nevra.Arch, sourceRPM[0], nevra.Version, nevra.Release, "openEuler-24.03")
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
		fmt.Println(fmt.Errorf("读取licenses时报错：%v", err))
	}
	fmt.Println("licenses: ", licenses)

	//-------url-------
	url, err := rpm.Header.GetStrings(rpmutils.URL)
	if err != nil {
		fmt.Println(fmt.Errorf("读取url时报错：%v", err))
	}
	fmt.Println("url: ", url)

	//-------rpmVersion-------
	rpmVersion, err := rpm.Header.GetStrings(rpmutils.RPMVERSION)
	if err != nil {
		fmt.Println(fmt.Errorf("读取rpmVersion时报错：%v", err))
	}
	fmt.Println("rpmVersion: ", rpmVersion)

	//-------description-------
	description, err := rpm.Header.GetStrings(rpmutils.DESCRIPTION)
	if err != nil {
		fmt.Println(fmt.Errorf("读取description时报错：%v", err))
	}
	fmt.Println("description: ", description)

	//-------packager-------
	packager, err := rpm.Header.GetStrings(rpmutils.PACKAGER)
	if err != nil {
		fmt.Println(fmt.Errorf("读取packager时报错：%v", err))
	}
	fmt.Println("packager: ", packager)

	//-------provides,提供的二进制包-------
	provides, err := rpm.Header.GetStrings(rpmutils.PROVIDENAME)
	if err != nil {
		fmt.Println(fmt.Errorf("读取provides时报错：%v", err))
	}
	//-------provideVersion-------
	provideVersion, err := rpm.Header.GetStrings(rpmutils.PROVIDEVERSION)
	if err != nil {
		fmt.Println(fmt.Errorf("读取provideVersion时报错：%v", err))
	}
	//-------provideFlags，获取版本符号（>=，<=等）-------
	provideFlags, err := rpm.Header.GetUint32s(rpmutils.PROVIDEFLAGS)
	packageList := []string{}
	if err != nil {
		fmt.Println(fmt.Errorf("读取provideFlags时报错：%v", err))
	}
	if len(provides) == len(provideVersion) && len(provideVersion) == len(provideFlags) {
		// 将可以打出的软件包名称和版本对应起来并输出
		fmt.Println("提供的软件包名称和版本:")
		for i := 0; i < len(provides); i++ {
			packageList = append(packageList, provides[i]+scan_utils.GetOperator(provideFlags[i])+provideVersion[i])
			fmt.Printf("名称: %s, 版本要求: %s %s\n", provides[i], scan_utils.GetOperator(provideFlags[i]), provideVersion[i])
		}
	} else {
		fmt.Println("提供的软件包名称、版本、符号数量不一致")
	}

	// ------------ 给pkg赋值 ------------
	metadata := _package.Metadata{}
	metadata.Lifecycle = _package.ReleaseLifecycle
	metadata.BomRef = bomRef
	metadata.Name = nevra.Name
	metadata.Version = nevra.Version
	metadata.Release = nevra.Release
	metadata.Arch = nevra.Arch
	metadata.PURL = purl
	metadata.Url = url[0]
	metadata.Description = description[0]
	metadata.License = licenses
	metadata.PackageList = strings.Join(packageList, ", ")

	metadata.SourcePkg = strings.Join(sourceRPM, ", ")
	metadata.Packager = packager[0]
	metadata.BuildTime = buildDate.String()
	metadata.BuildHost = strings.Join(buildHost, ", ")

	//-------require-------
	depends := []_package.Depend{}
	dependencyBomref := []string{}
	require, err := rpm.Header.GetStrings(rpmutils.REQUIRENAME)
	//require = removeItemFromSlice(require, "rpmlib(CompressedFileNames)")
	//require = removeItemFromSlice(require, "rpmlib(FileDigests)")
	if err != nil {
		fmt.Println(fmt.Errorf("读取require时报错：%v", err))
	}
	//-------requireFlags，获取版本符号（>=，<=等）-------
	requireFlags, err := rpm.Header.GetUint32s(rpmutils.REQUIREFLAGS)
	if err != nil {
		fmt.Println(fmt.Errorf("读取requireFlags时报错：%v", err))
	}
	//-------requireVersion-------
	requireVersion, err := rpm.Header.GetStrings(rpmutils.REQUIREVERSION)
	if err != nil {
		fmt.Println(fmt.Errorf("读取requireVersion时报错：%v", err))
	}
	if len(require) == len(requireVersion) && len(requireVersion) == len(requireFlags) {
		// 将依赖名称和版本对应起来并输出
		fmt.Println("依赖名称和版本:")
		versions := []string{}
		//拼接得到版本列表
		for i := 0; i < len(require); i++ {
			version := scan_utils.GetOperator(requireFlags[i]) + requireVersion[i]
			versions = append(versions, version)
			fmt.Printf("依赖: %s, 版本要求: %s\n", require[i], version)
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
				Name:    uniqueNames[i],
				Version: uniqueVersions[i],
				BomRef:  dependBomRef,
			})
			dependencyBomref = append(dependencyBomref, dependBomRef)
			fmt.Printf("依赖: %s, 版本要求: %s\n", uniqueNames[i], uniqueVersions[i])
		}
	} else {
		fmt.Println("依赖名称、版本、大小符号数量不一致")
	}

	directDependency := cyclonedx.Dependency{
		Ref:          bomRef,
		Dependencies: &dependencyBomref,
	}

	return nil, &_package.Pkg{
		Metadata:     &metadata,
		Depends:      &depends,
		Dependencies: &[]cyclonedx.Dependency{directDependency},
	}
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
