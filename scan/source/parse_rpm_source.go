package source

import (
	"compress/gzip"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/sassoftware/go-rpmutils"
	"io"
	"log"
	"os"
	_package "slp/package"
	"slp/utils"
	"strings"
	"time"

	"github.com/cavaliergopher/cpio"
	"github.com/cavaliergopher/rpm"
	"github.com/ulikunitz/xz"
)

// 提取.spec文件中的关键信息
func ParseSpecFile(content string) (name, version, release, sourceURL, hash, license, maintainer string) {
	//fmt.Println(content)
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		} else if strings.HasPrefix(line, "Version:") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		} else if strings.HasPrefix(line, "Release:") {
			release = strings.TrimSpace(strings.TrimPrefix(line, "Release:"))
		} else if strings.HasPrefix(line, "URL:") {
			sourceURL = strings.TrimSpace(strings.TrimPrefix(line, "URL:"))
		} else if strings.HasPrefix(line, "License:") {
			license = strings.TrimSpace(strings.TrimPrefix(line, "License:"))
		} else if strings.HasPrefix(line, "Packager:") {
			maintainer = strings.TrimSpace(strings.TrimPrefix(line, "Packager:"))
		} else if strings.Contains(line, "sha256:") {
			hash = strings.TrimSpace(strings.Split(line, "sha256:")[1])
		}
	}
	return
}

// 解析RPM包，提取RPM包中的.spec文件 并 返回一个包含了patch信息的map切片
func ReadRPMFile(rpmPath string) (specFileContent string, patchInfoMaps map[string]_package.Patch, err error) {

	file, err := os.Open(rpmPath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open RPM file: %v", err)
	}
	defer file.Close()

	// 使用cavaliergopher/rpm包读取RPM
	rpmPackage, err := rpm.Read(file)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read RPM: %v", err)
	}

	// 检查 rpm包 采用的压缩算法
	compression := rpmPackage.PayloadCompression()
	var reader io.Reader
	if compression == "xz" {
		reader, err = xz.NewReader(file)
		if err != nil {
			log.Fatal(err)
		}
	} else if compression == "gzip" {
		reader, err = gzip.NewReader(file)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}

		//tarReader := tar.NewReader(gzipReader)
	} else {
		log.Fatalf("Unsupported compression: %s", compression)
	}

	// 检查rpm包的格式是否是cpio
	if format := rpmPackage.PayloadFormat(); format != "cpio" {
		log.Fatalf("Unsupported payload format: %s", format)
	}

	cpioReader := cpio.NewReader(reader)
	patchInfoMaps = make(map[string]_package.Patch)
	for {
		header, err := cpioReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, fmt.Errorf("failed to read tar file: %v", err)
		}

		// 查找.spec文件
		if strings.HasSuffix(header.Name, ".spec") {
			var specContent strings.Builder
			if _, err := io.Copy(&specContent, cpioReader); err != nil {
				return "", nil, fmt.Errorf("failed to read spec file: %v", err)
			}
			specFileContent = specContent.String()
		}

		//查找并解析.patch文件、.diff文件
		if strings.HasSuffix(header.Name, ".patch") || strings.HasSuffix(header.Name, ".diff") {
			fmt.Println("文件名：", header.Name)
			var patchFileContent strings.Builder
			if _, err := io.Copy(&patchFileContent, cpioReader); err != nil {
				return "", nil, fmt.Errorf("failed to read patch file: %v", err)
			}

			patch := parsePatchFile(patchFileContent.String())
			patch.Name = header.Name
			patch.BomRef, err = _package.GetBomRef("patch:"+patch.Name, struct {
				Patch     _package.Patch
				timestamp time.Time //加上时间戳防止重复
			}{
				Patch:     patch,
				timestamp: time.Now(),
			}, "patch-id")
			patchInfoMaps[header.Name] = patch
		}
	}

	return specFileContent, patchInfoMaps, nil
}

// 解析rpm文件的header信息
func ParseSourceRpmFile(rpmPath string) (error, *_package.Pkg) {
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
		panic(fmt.Errorf("读取nevra时报错：%v", err))
	}
	fmt.Println("Name: ", nevra.Name)
	fmt.Println("Version: ", nevra.Version)
	fmt.Println("Release: ", nevra.Release)
	fmt.Println("Arch: ", nevra.Arch)

	// PURL
	purl := _package.RpmPackageURL(packageurl.TypeRPM, "openEuler", nevra.Name, nevra.Arch, "", nevra.Version, nevra.Release, "openEuler-24.03")
	fmt.Println("PURL: ", purl)

	//BOMRef
	bomRef, err := _package.GetBomRef(purl, struct {
		Name      string
		Version   string
		Release   string
		Arch      string
		timestamp time.Time //加上时间戳防止重复
	}{
		Name:      nevra.Name,
		Version:   nevra.Version,
		Release:   nevra.Release,
		Arch:      nevra.Arch,
		timestamp: time.Now(),
	}, "package-id")
	fmt.Println("BOMRef: ", bomRef)

	//-------licenses-------
	licenses, err := rpm.Header.GetStrings(rpmutils.LICENSE)
	if err != nil {
		panic(fmt.Errorf("读取licenses时报错：%v", err))
	}
	fmt.Println("licenses: ", licenses, len(licenses))

	//-------url-------
	url, err := rpm.Header.GetStrings(rpmutils.URL)
	if err != nil {
		panic(fmt.Errorf("读取url时报错：%v", err))
	}
	fmt.Println("url: ", url)

	//-------rpmVersion-------
	rpmVersion, err := rpm.Header.GetStrings(rpmutils.RPMVERSION)
	if err != nil {
		panic(fmt.Errorf("读取rpmVersion时报错：%v", err))
	}
	fmt.Println("rpmVersion: ", rpmVersion)

	//-------description-------
	description, err := rpm.Header.GetStrings(rpmutils.DESCRIPTION)
	if err != nil {
		panic(fmt.Errorf("读取description时报错：%v", err))
	}
	fmt.Println("description: ", description)

	//-------packager-------
	packager, err := rpm.Header.GetStrings(rpmutils.PACKAGER)
	if err != nil {
		panic(fmt.Errorf("读取packager时报错：%v", err))
	}
	fmt.Println("packager: ", packager)

	//-------source-------
	sources, err := rpm.Header.GetStrings(rpmutils.SOURCE)
	if err != nil {
		fmt.Println(fmt.Errorf("读取source时报错：%v", err))
	}
	fmt.Println("source: ", sources)

	//-------provides,源码包能够构建提供的二进制包-------
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
	metadata.Lifecycle = _package.SourceLifecycle
	metadata.BomRef = bomRef
	metadata.Name = nevra.Name
	metadata.Version = nevra.Version
	metadata.Release = nevra.Release
	metadata.Arch = nevra.Arch
	metadata.PURL = purl
	metadata.Url = url[0]
	metadata.Description = description[0]
	metadata.Sources = sources
	metadata.License = licenses[0]
	metadata.Packager = packager[0]
	metadata.PackageList = strings.Join(packageList, ",")

	//-------buildRequire-------
	buildDepends := []_package.BuildDepend{}
	dependencyBomref := []string{}
	buildRequire, err := rpm.Header.GetStrings(rpmutils.REQUIRENAME)
	//buildRequire = removeItemFromSlice(buildRequire, "rpmlib(CompressedFileNames)")
	//buildRequire = removeItemFromSlice(buildRequire, "rpmlib(FileDigests)")
	if err != nil {
		fmt.Println(fmt.Errorf("读取buildRequire时报错：%v", err))
	}
	//-------buildRequireFlags，获取版本符号（>=，<=等）-------
	buildRequireFlags, err := rpm.Header.GetUint32s(rpmutils.REQUIREFLAGS)
	if err != nil {
		fmt.Println(fmt.Errorf("读取buildRequireFlags时报错：%v", err))
	}
	//-------buildRequireVersion-------
	buildRequireVersion, err := rpm.Header.GetStrings(rpmutils.REQUIREVERSION)
	if err != nil {
		fmt.Println(fmt.Errorf("读取buildRequireVersion时报错：%v", err))
	}

	if len(buildRequire) == len(buildRequireVersion) && len(buildRequireVersion) == len(buildRequireFlags) {
		// 将依赖名称和版本对应起来并输出
		fmt.Println("依赖名称和版本:")
		for i := 0; i < len(buildRequire); i++ {
			version := scan_utils.GetOperator(buildRequireFlags[i]) + buildRequireVersion[i]
			buildRequireBomRef, _ := _package.GetBomRef("BuildRequire:"+buildRequire[i], struct {
				Name      string
				Version   string
				timestamp time.Time //加上时间戳防止重复
			}{
				Name:      buildRequire[i],
				Version:   version,
				timestamp: time.Now(),
			}, "package-id")
			buildDepends = append(buildDepends, _package.BuildDepend{
				Name:    buildRequire[i],
				Version: version,
				BomRef:  buildRequireBomRef,
			})
			dependencyBomref = append(dependencyBomref, buildRequireBomRef)
			fmt.Printf("依赖: %s, 版本要求: %s %s\n", buildRequire[i], scan_utils.GetOperator(buildRequireFlags[i]), buildRequireVersion[i])
		}
	} else {
		fmt.Println("依赖名称、版本、大小符号数量不一致")
	}

	//-------patches-------
	patches, err := rpm.Header.GetStrings(rpmutils.PATCH)
	if err != nil {
		fmt.Println(fmt.Errorf("读取patches时报错：%v", err))
	}
	fmt.Println("Patches: ", patches)
	// 从rpm文件中解压并提取每一个patch文件的内容
	_, patchInfoMap, err := ReadRPMFile(rpmPath)
	if err != nil {
		fmt.Println(fmt.Errorf("读取patch文件时报错：%v", err))
	}
	fmt.Println("patchInfoMaps: ", patchInfoMap)
	patchesList := []_package.Patch{}
	for _, patch := range patches {
		patchesList = append(patchesList, patchInfoMap[patch])
		fmt.Println("patch对应：", patch, patchInfoMap[patch])
	}

	directDependency := cyclonedx.Dependency{
		Ref:          bomRef,
		Dependencies: &dependencyBomref,
	}
	
	return nil, &_package.Pkg{
		Metadata:     &metadata,
		BuildDepends: &buildDepends,
		Patches:      &patchesList,
		Dependencies: &[]cyclonedx.Dependency{directDependency},
	}
}

// 从字符串切片中删除值为item的一项
func removeItemFromSlice(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

// 扫描patch文件获取patch元数据
func parsePatchFile(patchFileContent string) _package.Patch {
	var p _package.Patch
	subjectBuilder := strings.Builder{}
	lines := strings.Split(patchFileContent, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "From: ") {
			p.From = strings.TrimSpace(strings.TrimPrefix(line, "From:"))
		} else if strings.HasPrefix(line, "Date:") {
			p.Date = strings.TrimSpace(strings.TrimPrefix(line, "Date: "))
		} else if strings.HasPrefix(line, "Subject:") {
			p.Subject = strings.TrimSpace(strings.TrimPrefix(line, "Subject:"))
			subjectBuilder.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "Subject:")))
			//有时候Subject不止有一行，如果有跨行，后面的行会以空格开头
			for {
				i++
				if len(lines[i]) == 0 || lines[i][0] != ' ' {
					break
				}
				subjectBuilder.WriteString(" " + strings.TrimSpace(lines[i]))
			}
		}
	}
	p.Subject = strings.TrimSpace(subjectBuilder.String())
	return p
}
