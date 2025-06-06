package source

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	_package "slp/package"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"pault.ag/go/debian/control"
	"pault.ag/go/debian/dependency"
)

// 测试三方包解析dsc文件，未使用
func readDscFileByPault(dscFilePath string) {
	// 打开dsc文件
	file, err := os.Open(dscFilePath) // 替换为你的dsc文件路径
	if err != nil {
		log.Fatalf("Unable to open the file: %v", err)
	}
	defer file.Close()

	// 解析dsc文件
	var source control.DSC
	if err := control.Unmarshal(&source, file); err != nil {
		log.Fatalf("Unable to parse the dsc file: %v", err)
	}

	// 输出一些信息
	fmt.Printf("Package Name: %s\n", source.Source)
	fmt.Printf("Version: %s\n", source.Version)
	fmt.Printf("Maintainer: %s\n", source.Maintainer)
	fmt.Printf("Origin-Maintainer: %s\n", source.Origin)

	fmt.Printf("BuildDepends: %v\n", source.BuildDepends)
	fmt.Printf("Binaries: %v\n", source.Binaries)
	fmt.Printf("BuildDependsIndep: %v\n", source.BuildDependsIndep)
	fmt.Printf("Files: %v\n", source.Files)
	fmt.Printf("BuildDependsArch: %v\n", source.BuildDependsArch)
	fmt.Printf("Format: %v\n", source.Format)
	fmt.Printf("Architecture: %v\n", source.Architectures)

}

// 传入.dsc文件的路径，自己写方法解析,未使用
func readDscFile(filePath string) (map[string]string, error) {
	// Open the .dsc file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("could not open file: %v", err)
	}
	defer file.Close()

	// Initialize a map to hold the key-value pairs of control fields
	controlFields := make(map[string]string)
	scanner := bufio.NewScanner(file)
	var currentKey string

	// Read each line and parse key-value pairs
	for scanner.Scan() {
		line := scanner.Text()
		// If the line is empty, skip it (handle multiline values)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "Format:") {
			format := strings.TrimSpace(strings.Split(line, ":")[1])
			if format == "3.0 (native)" {
				controlFields["isNative"] = "IsNative" + "-" + line
			} else {
				controlFields["isNative"] = "NotNative" + "-" + line
			}
		}
		// Check if line is a new field
		if !strings.HasPrefix(line, " ") && strings.Contains(line, ":") {
			// Split the line by the first occurrence of ':'
			parts := strings.SplitN(line, ":", 2)
			currentKey = strings.TrimSpace(parts[0])
			controlFields[currentKey] = strings.TrimSpace(parts[1])
		} else if currentKey != "" {
			// If line starts with a space, it's a continuation of the previous field
			controlFields[currentKey] += " " + strings.TrimSpace(line)
		}

	}

	// Check for any scanner error
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading control file: %v", err)
	}

	return controlFields, nil
}

// 读取 `*/debian/patches/series` 文件内容，返回补丁文件列表
func readSeriesFile(seriesPath string) ([]string, error) {
	var patches []string

	file, err := os.Open(seriesPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 忽略注释行和空行
		if len(line) > 0 && line[0] != '#' {
			patches = append(patches, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	fmt.Println("-----------patches:--------------", patches)
	return patches, nil
}

// 传入patches文件夹的路径,按照series中应用的补丁列表解析所有的patch/diff文件
func parsePatchFiles(patchesDirPath string) (patches []_package.Patch, err error) {
	patchPaths, err := readSeriesFile(filepath.Join(patchesDirPath, "series"))
	patches = []_package.Patch{}
	if err != nil {
		return nil, fmt.Errorf("Unable to parse the Series file: %v", err)
	}
	for _, patchFile := range patchPaths {
		patchPath := filepath.Join(patchesDirPath, patchFile)
		content, err := ioutil.ReadFile(patchPath)
		if err != nil {
			return nil, err
		}
		patch := parsePatchFile(string(content))
		patch.Name = patchFile
		patch.BomRef, err = _package.GetBomRef("patch:"+patch.Name, struct {
			Patch     _package.Patch
			timestamp time.Time //加上时间戳防止重复
		}{
			Patch:     patch,
			timestamp: time.Now(),
		}, "patch-id")
		patches = append(patches, patch)
	}
	return
}

func ParseSourceDebFile(dscFilePath string, patchesDirPath string, copyrightFilePath string) (error, *_package.Pkg) {
	// 打开dsc文件
	file, err := os.Open(dscFilePath) // dsc文件路径
	if err != nil {
		return fmt.Errorf("Unable to open the dsc file.: %v", err), nil
	}
	defer file.Close()

	// 三方包解析dsc文件
	var dscFields control.DSC
	if err := control.Unmarshal(&dscFields, file); err != nil {
		return fmt.Errorf("Unable to parse the dsc file: %v", err), nil
	}

	// PURL
	// namespace: "ubuntu"; distro: "ubuntu-24.04"
	purl := _package.RpmPackageURL(packageurl.TypeDebian, "", dscFields.Source, "", "", dscFields.Version.String(), "", "")
	fmt.Println("PURL: ", purl)

	// BOMRef
	bomRef, err := _package.GetBomRef(purl, struct {
		Name         string
		Version      string
		Architecture []dependency.Arch
		timestamp    time.Time //加上时间戳防止重复
	}{
		Name:         dscFields.Source,
		Version:      dscFields.Version.String(),
		Architecture: dscFields.Architectures,
		timestamp:    time.Now(),
	}, "package-id")
	fmt.Println("BOMRef: ", bomRef)

	licenseList, err := parseLicensesFromCopyright(copyrightFilePath)
	if err != nil {
		fmt.Println("An error occurred while extracting the license:", err)
	}

	metadata := _package.Metadata{}
	metadata.Lifecycle = _package.SourceLifecycle
	metadata.BomRef = bomRef
	metadata.Name = dscFields.Source
	metadata.Version = dscFields.Version.String()
	metadata.PURL = purl
	metadata.Url = dscFields.Homepage
	metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", metadata.Name, metadata.Version)
	metadata.License = licenseList
	sources := []string{}
	for _, file := range dscFields.Files {
		sources = append(sources, file.Filename)
	}
	metadata.Sources = sources
	metadata.Maintainer = dscFields.Maintainer
	metadata.OriginalMaintainer = dscFields.Origin
	// 去除每个元素的首尾空白字符
	packageList := []string{}
	for _, binary := range dscFields.Binaries {
		packageList = append(packageList, strings.TrimSpace(binary))
	}
	metadata.PackageList = strings.Join(packageList, ",")
	if dscFields.Format == "3.0 (native)" {
		metadata.IsNative = "IsNative" + "-" + dscFields.Format
	} else {
		metadata.IsNative = "NotNative" + "-" + dscFields.Format
	}
	architecture := ""
	for _, arch := range dscFields.Architectures {
		architecture += arch.String()
	}
	metadata.Architecture = architecture

	// --------------- 构建依赖 ---------------
	buildDepends := []_package.BuildDepend{}
	dependencyBomref := []string{}
	for _, d := range dscFields.BuildDepends.Relations {
		for _, p := range d.Possibilities {
			fmt.Println("Possibility:", p.Name, p.Version)
			version := ""
			if p.Version != nil {
				version = p.Version.Operator + " " + p.Version.Number
			}
			buildDependBomRef, _ := _package.GetBomRef("Build-Depend:"+p.Name, struct {
				Name      string
				Version   string
				timestamp time.Time //加上时间戳防止重复
			}{
				Name:      p.Name,
				Version:   version,
				timestamp: time.Now(),
			}, "package-id")
			buildDepends = append(buildDepends, _package.BuildDepend{
				Metadata: _package.Metadata{
					Name:    p.Name,
					Version: version,
					BomRef:  buildDependBomRef,
				},
				DebBuildDependType: "Build-Depends",
			})
			dependencyBomref = append(dependencyBomref, buildDependBomRef)
		}
	}
	for _, d := range dscFields.BuildDependsIndep.Relations {
		for _, p := range d.Possibilities {
			fmt.Println("Possibility:", p.Name, p.Version)
			version := ""
			if p.Version != nil {
				version = p.Version.Operator + " " + p.Version.Number
			}
			buildDependBomRef, _ := _package.GetBomRef("Build-Depend-Indep:"+p.Name, struct {
				Name      string
				Version   string
				timestamp time.Time //加上时间戳防止重复
			}{
				Name:      p.Name,
				Version:   version,
				timestamp: time.Now(),
			}, "package-id")
			buildDepends = append(buildDepends, _package.BuildDepend{
				Metadata: _package.Metadata{
					Name:    p.Name,
					Version: version,
					BomRef:  buildDependBomRef,
				},
				DebBuildDependType: "Build-Depends-Indep",
			})
			dependencyBomref = append(dependencyBomref, buildDependBomRef)
		}
	}
	for _, d := range dscFields.BuildDependsArch.Relations {
		for _, p := range d.Possibilities {
			fmt.Println("Possibility:", p.Name, p.Version)
			version := ""
			if p.Version != nil {
				version = p.Version.Operator + " " + p.Version.Number
			}
			buildDependBomRef, _ := _package.GetBomRef("Build-Depend-Arch:"+p.Name, struct {
				Name      string
				Version   string
				timestamp time.Time //加上时间戳防止重复
			}{
				Name:      p.Name,
				Version:   version,
				timestamp: time.Now(),
			}, "package-id")
			buildDepends = append(buildDepends, _package.BuildDepend{
				Metadata: _package.Metadata{
					Name:    p.Name,
					Version: version,
					BomRef:  buildDependBomRef,
				},
				DebBuildDependType: "Build-Depends-Arch",
			})
			dependencyBomref = append(dependencyBomref, buildDependBomRef)
		}
	}

	patches, err := parsePatchFiles(patchesDirPath)

	directDependency := cyclonedx.Dependency{
		Ref:          bomRef,
		Dependencies: &dependencyBomref,
	}

	return nil, &_package.Pkg{
		Metadata:     &metadata,
		BuildDepends: &buildDepends,
		Patches:      &patches,
		Dependencies: &[]cyclonedx.Dependency{directDependency},
	}
}
