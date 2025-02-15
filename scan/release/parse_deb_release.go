package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/blakesmith/ar"           // 用于解压 deb 文件
	"github.com/klauspost/compress/zstd" // 用于解压 zstd 格式
	"github.com/package-url/packageurl-go"
	"github.com/ulikunitz/xz" // 用于解压 xz 格式
	"io"
	"log"
	"os"
	"pault.ag/go/debian/deb"
	"pault.ag/go/debian/dependency"
	_package "slp/package"
	"slp/scan/source"
	"strings"
	"time"
)

// 解压deb文件，获得control文件，或者buildEnv.json文件
// fileName参数传入："control.tar" 时是获取control文件
// fileName参数传入："data.tar" 时是获取buildEnv.json文件
func extractFileFromDeb(debFilePath string, fileName string) (map[string]string, *source.DebBuildEnv, error) {
	file, err := os.Open(debFilePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	arReader := ar.NewReader(file)

	// Loop through the .deb file to find control.tar.zst or control.tar.gz
	for {
		header, err := arReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, err
		}

		// 从第一层压缩文件中找到 control.tar.zst或者data.tar.zst
		if strings.HasPrefix(header.Name, fileName) {
			fileData := new(bytes.Buffer)
			if _, err := io.Copy(fileData, arReader); err != nil {
				return nil, nil, err
			}
			// zst/gz/xz三种压缩方式，分别处理
			if strings.HasSuffix(header.Name, ".zst") {
				zstdReader, err := zstd.NewReader(fileData)
				if err != nil {
					return nil, nil, err
				}
				defer zstdReader.Close()

				unzstdData := new(bytes.Buffer)
				if _, err := io.Copy(unzstdData, zstdReader); err != nil {
					return nil, nil, err
				}
				if fileName == "control.tar" {
					err, controlData := parseControlFile(unzstdData.Bytes())
					if err != nil {
						return nil, nil, err
					}
					return controlData, nil, nil
				} else if fileName == "data.tar" {
					err, buildEnv := parseBuildEnvFile(unzstdData.Bytes())
					if err != nil {
						return nil, nil, err
					}
					return nil, buildEnv, nil
				}
			} else if strings.HasSuffix(header.Name, ".gz") {
				gzReader, err := gzip.NewReader(fileData)
				if err != nil {
					return nil, nil, err
				}
				defer gzReader.Close()

				unzippedData := new(bytes.Buffer)
				if _, err := io.Copy(unzippedData, gzReader); err != nil {
					return nil, nil, err
				}
				if fileName == "control.tar" {
					err, controlData := parseControlFile(unzippedData.Bytes())
					if err != nil {
						return nil, nil, err
					}
					return controlData, nil, nil
				} else if fileName == "data.tar" {
					err, buildEnv := parseBuildEnvFile(unzippedData.Bytes())
					if err != nil {
						return nil, nil, err
					}
					return nil, buildEnv, nil
				}
			} else if strings.HasSuffix(header.Name, ".xz") {
				xzReader, err := xz.NewReader(fileData)
				if err != nil {
					return nil, nil, err
				}

				unxzData := new(bytes.Buffer)
				if _, err := io.Copy(unxzData, xzReader); err != nil {
					return nil, nil, err
				}
				if fileName == "control.tar" {
					err, controlData := parseControlFile(unxzData.Bytes())
					if err != nil {
						return nil, nil, err
					}
					return controlData, nil, nil
				} else if fileName == "data.tar" {
					err, buildEnv := parseBuildEnvFile(unxzData.Bytes())
					if err != nil {
						return nil, nil, err
					}
					return nil, buildEnv, nil
				}
			}
			break
		}
	}
	if fileName == "control.tar" {
		return nil, nil, fmt.Errorf("未发现control文件")
	} else {
		return nil, nil, fmt.Errorf("未发现buildEnv.json文件")
	}
}

// Function to parse metadata from control file
func parseControlFile(controlData []byte) (error, map[string]string) {
	metadata := make(map[string]string)
	tarReader := tar.NewReader(bytes.NewReader(controlData))

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err, nil
		}
		// Find the control file which usually contains metadata
		if strings.HasSuffix(header.Name, "control") {
			var controlContent bytes.Buffer
			if _, err := io.Copy(&controlContent, tarReader); err != nil {
				log.Fatal(err)
			}

			// Parse control file line by line
			lines := strings.Split(controlContent.String(), "\n")
			for _, line := range lines {
				fmt.Println(line)
				if len(line) == 0 || !strings.Contains(line, ":") {
					continue
				}
				parts := strings.SplitN(line, ":", 2)
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				metadata[key] = value
			}
		}
	}

	return nil, metadata
}

func parseBuildEnvFile(buildEnvData []byte) (error, *source.DebBuildEnv) {
	tarReader := tar.NewReader(bytes.NewReader(buildEnvData))
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err, nil
		}
		// 通过文件名找到buildEnv.json文件，并将其解析
		if strings.HasSuffix(header.Name, "buildEnv.json") {
			var sbom source.DebBuildEnv
			decoder := json.NewDecoder(tarReader)
			err = decoder.Decode(&sbom)
			if err != nil {
				return err, nil
			}
			return nil, &sbom
		}
	}
	return fmt.Errorf("未发现buildEnv.json文件"), nil
}

func ParseReleaseDebFile(debFilePath string) (error, *_package.Pkg) {
	// Parse metadata from control file
	controlData, _, err := extractFileFromDeb(debFilePath, "control.tar")
	if err != nil {
		return fmt.Errorf("Failed to extract control file: %v", err), nil
	}

	fmt.Println("Parsed Control Fields:")
	for key, value := range controlData {
		fmt.Printf("%s: %s\n", key, value)
	}

	metadata := _package.Metadata{}

	//判断上游源码包
	value, exists := controlData["Source"]
	if exists {
		metadata.SourcePkg = value
	} else {
		metadata.SourcePkg = controlData["Package"]
	}
	// PURL
	// namespace: "ubuntu"; distro: "ubuntu-24.04"
	purl := _package.RpmPackageURL(packageurl.TypeDebian, "", controlData["Package"], controlData["Architecture"], metadata.SourcePkg, controlData["Version"], "", "")
	fmt.Println("PURL: ", purl)

	// BOMRef
	bomRef, err := _package.GetBomRef(purl, struct {
		Name         string
		Version      string
		Architecture string
		timestamp    time.Time //加上时间戳防止重复
	}{
		Name:         controlData["Package"],
		Version:      controlData["Version"],
		Architecture: controlData["Architecture"],
		timestamp:    time.Now(),
	}, "package-id")
	fmt.Println("BOMRef: ", bomRef)

	metadata.Lifecycle = _package.ReleaseLifecycle
	metadata.BomRef = bomRef
	metadata.Name = controlData["Package"]
	metadata.Version = controlData["Version"]
	metadata.Architecture = controlData["Architecture"]
	metadata.PURL = purl
	metadata.Url = controlData["Homepage"]
	metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", metadata.Name, metadata.Version)

	// 引入"pault.ag/go/debian/deb"三方包读取Description、
	file, err := os.Open(debFilePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	debFile, err := deb.Load(file, debFilePath)
	if err != nil {
		log.Fatal(err)
	}
	// 提取Description
	metadata.Description = debFile.Control.Description
	metadata.Maintainer = controlData["Maintainer"]
	metadata.OriginalMaintainer = controlData["Original-Maintainer"]
	metadata.Section = controlData["Section"]
	metadata.Priority = controlData["Priority"]

	var depends []_package.Depend
	dependencyBomref := []string{}
	if controlData["Depends"] != "" {
		dep, err := dependency.Parse(controlData["Depends"])
		if err != nil {
			return fmt.Errorf("使用dependency解析Depends依赖发生错误: %v", err), nil
		}
		//possibilities := dep.GetAllPossibilities()
		for _, d := range dep.Relations {
			for _, p := range d.Possibilities {
				fmt.Println("Possibility:", p.Name, p.Version)
				version := ""
				if p.Version != nil {
					version = p.Version.Operator + " " + p.Version.Number
				}
				dependBomRef, _ := _package.GetBomRef("Depend:"+p.Name, struct {
					Name      string
					Version   string
					timestamp time.Time //加上时间戳防止重复
				}{
					Name:      p.Name,
					Version:   version,
					timestamp: time.Now(),
				}, "package-id")
				depends = append(depends, _package.Depend{
					Metadata: _package.Metadata{
						Name:    p.Name,
						Version: version,
						BomRef:  dependBomRef,
					},
					DebDependType: "Depends",
				})
				dependencyBomref = append(dependencyBomref, dependBomRef)
			}
		}
	}

	if controlData["Pre-Depends"] != "" {
		dep, err := dependency.Parse(controlData["Pre-Depends"])
		if err != nil {
			return fmt.Errorf("使用dependency解析Pre-Depends依赖发生错误: %v", err), nil
		}
		//possibilities := dep.GetAllPossibilities()
		for _, d := range dep.Relations {
			for _, p := range d.Possibilities {
				fmt.Println("Possibility:", p.Name, p.Version)
				version := ""
				if p.Version != nil {
					version = p.Version.Operator + " " + p.Version.Number
				}
				dependBomRef, _ := _package.GetBomRef("Pre-Depend:"+p.Name, struct {
					Name      string
					Version   string
					timestamp time.Time //加上时间戳防止重复
				}{
					Name:      p.Name,
					Version:   version,
					timestamp: time.Now(),
				}, "package-id")
				depends = append(depends, _package.Depend{
					Metadata: _package.Metadata{
						Name:    p.Name,
						Version: version,
						BomRef:  dependBomRef,
					},
					DebDependType: "Pre-Depends",
				})
				dependencyBomref = append(dependencyBomref, dependBomRef)
			}
		}
	}

	if controlData["Built-Using"] != "" {
		dep, err := dependency.Parse(controlData["Built-Using"])
		if err != nil {
			return fmt.Errorf("使用dependency解析Built-Using依赖发生错误: %v", err), nil
		}
		//possibilities := dep.GetAllPossibilities()
		for _, d := range dep.Relations {
			for _, p := range d.Possibilities {
				fmt.Println("Possibility:", p.Name, p.Version)
				version := ""
				if p.Version != nil {
					version = p.Version.Operator + " " + p.Version.Number
				}
				dependBomRef, _ := _package.GetBomRef("Built-Using:"+p.Name, struct {
					Name      string
					Version   string
					timestamp time.Time //加上时间戳防止重复
				}{
					Name:      p.Name,
					Version:   version,
					timestamp: time.Now(),
				}, "package-id")
				depends = append(depends, _package.Depend{
					Metadata: _package.Metadata{
						Name:    p.Name,
						Version: version,
						BomRef:  dependBomRef,
					},
					DebDependType: "Built-Using",
				})
				dependencyBomref = append(dependencyBomref, dependBomRef)
			}
		}
	}

	directDependency := cyclonedx.Dependency{
		Ref:          bomRef,
		Dependencies: &dependencyBomref,
	}

	// Parse build-depends from buildEnv.json file
	_, buildEnv, err := extractFileFromDeb(debFilePath, "data.tar")
	if err != nil {
		return fmt.Errorf("Failed to extract buildEnv.json file: %v", err), nil
	}
	var buildDeps []_package.BuildDepend

	//依赖可能存在 "|" 的关系，所以bdList也可能有多项
	for _, bdList := range buildEnv.BuildDepends {
		buildDeps = append(buildDeps, envBdToBd(bdList, "Build-Depends")...)
	}
	for _, bdList := range buildEnv.BuildDependsIndep {
		fmt.Println(bdList)
		buildDeps = append(buildDeps, envBdToBd(bdList, "Build-Depends-Indep")...)
	}
	for _, bdList := range buildEnv.BuildDependsArch {
		fmt.Println(bdList)
		buildDeps = append(buildDeps, envBdToBd(bdList, "Build-Depends-Arch")...)
	}

	return nil, &_package.Pkg{
		Metadata:     &metadata,
		Depends:      &depends,
		BuildDepends: &buildDeps,
		Dependencies: &[]cyclonedx.Dependency{directDependency},
	}
}

func envBdToBd(bdList source.BuildDepPkgGroup, buildDependType string) []_package.BuildDepend {
	var buildDeps []_package.BuildDepend
	if len(bdList) == 1 {
		buildDeps = append(buildDeps, _package.BuildDepend{
			Metadata:           *bdList[0].Metadata,
			DebBuildDependType: buildDependType,
		})
	} else {
		//拼接或依赖关系描述
		var orRelation string
		for i, bd := range bdList {
			if i != 0 { // 如果不是第一个元素，添加分隔符
				orRelation += " | "
			}
			orRelation += bd.Metadata.Name
		}
		for _, bd := range bdList {
			buildDeps = append(buildDeps, _package.BuildDepend{
				Metadata:              *bd.Metadata,
				DebBuildDependType:    buildDependType,
				VirtualOrConcreteDesc: orRelation,
			})
		}
	}
	return buildDeps
}
