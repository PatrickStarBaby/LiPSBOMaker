package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/blakesmith/ar"           // 用于解压 deb 文件
	"github.com/klauspost/compress/zstd" // 用于解压 zstd 格式
	"github.com/package-url/packageurl-go"
	"io"
	"log"
	"os"
	"pault.ag/go/debian/deb"
	"pault.ag/go/debian/dependency"
	_package "slp/package"
	"strings"
	"time"
)

// Function to extract the control file from a deb package
func extractControlFile(debFilePath string) ([]byte, error) {
	file, err := os.Open(debFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	arReader := ar.NewReader(file)
	var controlFile []byte

	// Loop through the .deb file to find control.tar.zst or control.tar.gz
	for {
		header, err := arReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}

		// Check if the file is control.tar.zst or control.tar.gz
		if strings.HasPrefix(header.Name, "control.tar") {
			controlData := new(bytes.Buffer)
			if _, err := io.Copy(controlData, arReader); err != nil {
				return nil, err
			}

			if strings.HasSuffix(header.Name, ".zst") {
				zstdReader, err := zstd.NewReader(controlData)
				if err != nil {
					return nil, err
				}
				defer zstdReader.Close()

				unzstdData := new(bytes.Buffer)
				if _, err := io.Copy(unzstdData, zstdReader); err != nil {
					return nil, err
				}
				controlFile = unzstdData.Bytes()

			} else if strings.HasSuffix(header.Name, ".gz") {
				gzReader, err := gzip.NewReader(controlData)
				if err != nil {
					return nil, err
				}
				defer gzReader.Close()

				unzippedData := new(bytes.Buffer)
				if _, err := io.Copy(unzippedData, gzReader); err != nil {
					return nil, err
				}
				controlFile = unzippedData.Bytes()
			}
			break
		}
	}
	return controlFile, nil
}

// Function to parse metadata from control file
func parseControlFile(controlData []byte) map[string]string {
	metadata := make(map[string]string)
	tarReader := tar.NewReader(bytes.NewReader(controlData))

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
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

	return metadata
}

func ParseReleaseDebFile(debFilePath string) (error, *_package.Pkg) {
	// Step 1: Extract control file data from deb package
	controlFileContent, err := extractControlFile(debFilePath)
	if err != nil {
		return fmt.Errorf("Failed to extract control file: %v", err), nil
	}

	// Step 2: Parse metadata from control file
	controlData := parseControlFile(controlFileContent)

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
	purl := _package.RpmPackageURL(packageurl.TypeDebian, "ubuntu", controlData["Package"], controlData["Architecture"], metadata.SourcePkg, controlData["Version"], "", "ubuntu-24.04")
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

	return nil, &_package.Pkg{
		Metadata:     &metadata,
		Depends:      &depends,
		Dependencies: &[]cyclonedx.Dependency{directDependency},
	}
}
