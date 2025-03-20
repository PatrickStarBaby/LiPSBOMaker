package image

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/package-url/packageurl-go"
	"io"
	_ "modernc.org/sqlite" // 替换 mattn/go-sqlite3 驱动
	"os"
	"path/filepath"
	"regexp"
	_package "slp/package"
	pkg "slp/package"
	scan_utils "slp/utils"
	"sort"
	"strings"
	"time"
)

// 添加自定义结构体用于确保输出的JSON字段顺序正确
type ComponentOutput struct {
	BOMRef       string                   `json:"bom-ref,omitempty"`
	Name         string                   `json:"name,omitempty"`
	PURL         string                   `json:"purl,omitempty"`
	Type         string                   `json:"type,omitempty"`
	Version      string                   `json:"version,omitempty"`
	CPE          string                   `json:"cpe,omitempty"`
	Architecture string                   `json:"architecture,omitempty"`
	Licenses     []map[string]interface{} `json:"licenses,omitempty"`
	Properties   []map[string]string      `json:"properties,omitempty"`
	// 添加外部引用字段
	ExternalReferences []map[string]string `json:"externalReferences,omitempty"`
	// 内核专用字段
	BuildTime string `json:"buildTime,omitempty"`
}

// 依赖关系结构体，确保ref字段在dependsOn之前
type DependencyOutput struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// 工具组件结构体
type ToolComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// 工具信息结构体
type ToolsInfo struct {
	Components []ToolComponent `json:"components"`
}

type MainMetadata struct {
	CraeateTime string          `json:"timestamp"`
	Tools       ToolsInfo       `json:"tools"`
	Component   ComponentOutput `json:"component"`
}

// SBOM格式的输出结构
type outputSBOM struct {
	Schema       string             `json:"$schema"`
	BomFormat    string             `json:"bomFormat"`
	SpecVersion  string             `json:"specVersion"`
	SerialNumber string             `json:"serialNumber"`
	Version      int                `json:"version"`
	MainMetadata MainMetadata       `json:"metadata"`
	Components   []ComponentOutput  `json:"components"`
	Dependencies []DependencyOutput `json:"dependencies,omitempty"`
}

// ScanResult 存储扫描结果
type ScanResult struct {
	OsType      string                  `json:"osType"`
	Kernel      *pkg.LinuxKernel        `json:"kernel,omitempty"`
	Packages    *pkg.Pkg                `json:"packages,omitempty"`
	PackageMap  map[string]*PackageInfo `json:"package_map,omitempty"` // 添加包映射字段
	AllPackages []*pkg.Metadata         `json:"-"`                     // 存储所有包的元数据，不输出到JSON
}

// PackageInfo 存储软件包信息用于依赖分析
type PackageInfo struct {
	BOMRef   string   // BOM引用ID
	Name     string   // 包名
	Provides []string // 包提供的功能
	Depends  []string // 包依赖的功能
}

// 全局变量定义
var (
	globalPackageInfoMap  map[string]*PackageInfo // 全局包信息映射
	allDiscoveredPackages []*pkg.Metadata         // 存储所有发现的包信息
	quietMode             bool                    // 安静模式标志
)

// 添加进度条显示函数
func showProgress(percent int, message ...string) {
	if quietMode {
		return
	}
	const width = 50
	progress := width * percent / 100

	// 如果有消息需要显示
	if len(message) > 0 && message[0] != "" {
		// 先清除当前行
		fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
		// 显示消息
		fmt.Println(message[0])
	}

	// 显示进度条
	fmt.Printf("\r[%s%s] %d%%",
		strings.Repeat("=", progress),
		strings.Repeat(" ", width-progress),
		percent)
}

// 设置安静模式
func SetQuietMode(quiet bool) {
	quietMode = quiet
}

func init() {
	// 初始化全局变量
	globalPackageInfoMap = make(map[string]*PackageInfo)
	allDiscoveredPackages = make([]*pkg.Metadata, 0)
	quietMode = false // 默认非安静模式
}

func ParseImageFile(path string) error {
	// 初始化进度为0%
	showProgress(0)

	// 检查 docker image 是否存在
	_, err := scan_utils.RunCommand("docker", "inspect", path)
	if err != nil {
		return fmt.Errorf("\ndocker镜像不存在: %v", err)
	}

	// 显示进度 - 镜像检查完成
	showProgress(5)

	// 创建临时目录用于保存提取的文件
	tmpDir, err := os.MkdirTemp("", "docker_files_*")
	if err != nil {
		return fmt.Errorf("\n创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// 创建一个临时容器
	showProgress(10)
	containerID, err := scan_utils.RunCommand("docker", "create", path)
	if err != nil {
		return fmt.Errorf("\n创建临时容器失败: %v", err)
	}
	containerID = strings.TrimSpace(containerID)

	// 使用完后删除容器
	defer func() {
		_, _ = scan_utils.RunCommand("docker", "rm", "-f", containerID)
	}()

	// 更新进度 - 容器创建完成
	showProgress(15)

	// 直接使用docker命令获取系统信息，而不是复制文件
	osReleaseOutput, err := scan_utils.RunCommand("docker", "run", "--rm", path, "cat", "/etc/os-release")
	if err != nil {
		osReleaseOutput = ""
	}

	// 解析os-release输出获取NAME字段
	osRelease := strings.ToLower(osReleaseOutput)
	var osType string

	// 从os-release中解析NAME字段
	namePattern := regexp.MustCompile(`(?m)^NAME="([^"]+)"`)
	nameMatches := namePattern.FindStringSubmatch(osReleaseOutput)

	if len(nameMatches) >= 2 {
		nameValue := strings.ToLower(nameMatches[1])

		// 根据NAME字段确定操作系统类型
		switch {
		case strings.Contains(nameValue, "debian"):
			osType = "debian"
		case strings.Contains(nameValue, "ubuntu"):
			osType = "ubuntu"
		case strings.Contains(nameValue, "fedora"):
			osType = "fedora"
		case strings.Contains(nameValue, "openeuler"):
			osType = "openeuler"
		default:
			return fmt.Errorf("\n不支持的操作系统类型: %s", nameMatches[1])
		}
	} else {
		// 如果无法提取NAME字段，尝试从整个os-release内容判断
		if strings.Contains(osRelease, "debian") {
			osType = "debian"
		} else if strings.Contains(osRelease, "ubuntu") {
			osType = "ubuntu"
		} else if strings.Contains(osRelease, "fedora") {
			osType = "fedora"
		} else if strings.Contains(osRelease, "openeuler") {
			osType = "openeuler"
		} else {
			// 如果无法从os-release判断，不应该假设系统类型
			return fmt.Errorf("\n无法确定操作系统类型，不支持的系统")
		}
	}

	// 更新进度 - 系统类型确定
	showProgress(20)

	// 根据发行版类型处理
	if osType == "fedora" {
		// 显示Fedora系统类型，同时更新进度为25%
		showProgress(25, "开始解析Fedora系统，这将需要一些时间...")

		// 获取内核信息
		showProgress(30)
		kernelInfo, err := parseKernelInfo(path)
		if err != nil {
			return fmt.Errorf("\n获取内核信息失败: %v", err)
		}

		// 解析RPM包信息
		showProgress(35)
		pkgInfo, err := parseRpmViaDocker(path)
		if err != nil {
			return fmt.Errorf("\n解析Fedora包信息失败: %v", err)
		}

		// 创建扫描结果结构体
		scanResult := &ScanResult{
			Kernel:      kernelInfo,
			Packages:    pkgInfo,
			PackageMap:  globalPackageInfoMap,  // 使用全局变量
			AllPackages: allDiscoveredPackages, // 使用全局包数组
		}

		// 将结果转换为SBOM格式
		showProgress(95)
		sbomOutput := convertToSBOMFormat(scanResult)

		// 使用自定义编码器来避免转义URL中的&字符
		buffer := &bytes.Buffer{}
		encoder := json.NewEncoder(buffer)
		encoder.SetEscapeHTML(false) // 这是关键设置：不转义HTML字符如&
		encoder.SetIndent("", "    ")
		if err := encoder.Encode(sbomOutput); err != nil {
			return fmt.Errorf("\n转换JSON失败: %v", err)
		}

		// 正确定义输出文件名
		outputFilename := fmt.Sprintf(osType + "-SBOM.json")

		// 创建输出文件
		err = os.WriteFile(outputFilename, buffer.Bytes(), 0644)
		if err != nil {
			return fmt.Errorf("\n写入结果文件失败: %v", err)
		}

		// 显示100%进度并输出完成信息
		showProgress(100)
		if !quietMode {
			// 添加换行并显示完成信息
			fmt.Println("\nSBOM文件已生成：" + outputFilename)
		}
		return nil
	}

	// 其他系统类型的处理...
	// 保留原有代码
	var targetDbPath string
	var localDbPath string

	// 根据发行版类型设置对应的数据库文件路径
	switch osType {
	case "debian", "ubuntu": // Debian/Ubuntu使用相同的路径
		targetDbPath = "/var/lib/dpkg/status"
		localDbPath = filepath.Join(tmpDir, "dpkg-status")
	case "openeuler": // OpenEuler
		targetDbPath = "/var/lib/rpm/Packages.db"
		localDbPath = filepath.Join(tmpDir, "Packages.db")
	default:
		return fmt.Errorf("\n不支持的操作系统类型: %s", osType)
	}

	showProgress(25)
	_, err = scan_utils.RunCommand("docker", "cp", fmt.Sprintf("%s:%s", containerID, targetDbPath), localDbPath)
	if err != nil {
		return fmt.Errorf("\n复制数据库文件失败: %v", err)
	}

	// 检查目标文件是否存在
	if _, err := os.Stat(localDbPath); os.IsNotExist(err) {
		return fmt.Errorf("\n复制数据库文件后目标文件不存在: %s", localDbPath)
	}

	// 获取内核信息 - 使用容器命令
	showProgress(30)
	kernelInfo, err := parseKernelInfo(path)
	if err != nil {
		return fmt.Errorf("\n获取内核信息失败: %v", err)
	}

	// 解析包管理数据库
	var pkgInfo *pkg.Pkg
	showProgress(35)
	switch {
	case strings.HasSuffix(localDbPath, "dpkg-status"):
		// 对于Debian/Ubuntu，需要获取copyright文件信息
		// 创建一个本地目录存放copyright文件
		copyrightDir := filepath.Join(tmpDir, "copyright")
		err = os.MkdirAll(copyrightDir, 0755)
		if err == nil {
			// 获取已安装的软件包列表
			installedPkgs, err := getInstalledPackages(localDbPath)
			if err == nil {
				// 逐个复制copyright文件
				totalPkgs := len(installedPkgs)
				for i, pkgName := range installedPkgs {
					srcPath := fmt.Sprintf("%s:/usr/share/doc/%s/copyright", containerID, pkgName)
					destPath := filepath.Join(copyrightDir, pkgName)
					_, _ = scan_utils.RunCommand("docker", "cp", srcPath, destPath)

					// 更新进度 - 更细致的进度展示
					progress := 35 + int(float64(i+1)/float64(totalPkgs)*25)
					showProgress(progress)
				}
			}
		}
		pkgInfo, err = parseDpkgStatus(localDbPath, copyrightDir, path)
	case strings.HasSuffix(localDbPath, "rpmdb.sqlite"):
		pkgInfo, err = parseRpmSqlite(localDbPath, path)
	case strings.HasSuffix(localDbPath, "Packages.db"):
		pkgInfo, err = parseRpmDb(localDbPath, path)
	}

	// 如果解析失败
	if err != nil {
		return fmt.Errorf("\n解析包管理数据库失败: %v", err)
	}

	showProgress(70)

	// 创建扫描结果结构体
	scanResult := &ScanResult{
		OsType:      osType,
		Kernel:      kernelInfo,
		Packages:    pkgInfo,
		PackageMap:  globalPackageInfoMap,  // 使用全局变量
		AllPackages: allDiscoveredPackages, // 使用全局包数组
	}

	// 将结果转换为SBOM格式
	showProgress(80)
	sbomOutput := convertToSBOMFormat(scanResult)

	// 使用自定义编码器来避免转义URL中的&字符
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false) // 这是关键设置：不转义HTML字符如&
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(sbomOutput); err != nil {
		return fmt.Errorf("\n转换JSON失败: %v", err)
	}

	showProgress(90)
	// 正确定义输出文件名
	outputFilename := fmt.Sprintf(osType + "-SBOM.json")

	// 创建输出文件
	err = os.WriteFile(outputFilename, buffer.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("\n写入结果文件失败: %v", err)
	}

	// 更新进度为100%并显示完成信息
	showProgress(100)
	if !quietMode {
		// 添加换行并显示完成信息
		fmt.Println("\nSBOM文件已生成：" + outputFilename)
	}
	return nil
}

// getInstalledPackages 从dpkg status文件获取已安装的包列表
func getInstalledPackages(statusFile string) ([]string, error) {
	content, err := os.ReadFile(statusFile)
	if err != nil {
		return nil, err
	}

	contentStr := string(content)
	packagePattern := regexp.MustCompile(`(?m)^Package: (.+)$`)
	matches := packagePattern.FindAllStringSubmatch(contentStr, -1)

	var packages []string
	for _, match := range matches {
		if len(match) >= 2 {
			packages = append(packages, match[1])
		}
	}

	return packages, nil
}

// parseDpkgStatus 使用dpkg status文件解析包信息
func parseDpkgStatus(filePath string, copyrightDir string, imagePath string) (*pkg.Pkg, error) {
	// 读取dpkg status文件
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("\n读取dpkg status文件失败: %v", err)
	}

	// 直接使用字符串读取，确保处理所有包
	contentStr := string(content)

	// 获取系统信息用于生成 PURL
	var distro string

	// 尝试获取系统信息从docker命令
	osReleaseOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "cat", "/etc/os-release")
	if err == nil {
		// 仅获取distro部分
		_, distro = parseOsInfo(osReleaseOutput)
	} else {
		// 如果获取失败，使用默认值
		distro = "debian"
	}

	// 按"Package: "前缀分割，更准确地分隔每个包
	// 先用一个特殊标记替换所有"Package: "，然后按这个标记分割
	// 由于第一个包前面也有"Package: "，我们先加一个标记以保留
	specialMarker := "###PACKAGE_MARKER###"
	markedContent := strings.Replace(contentStr, "Package: ", specialMarker+"Package: ", -1)

	// 分割后的包块
	pkgBlocks := strings.Split(markedContent, specialMarker)
	// 第一个元素是空的，因为文件开头就有"Package: "，去掉它
	if len(pkgBlocks) > 0 && pkgBlocks[0] == "" {
		pkgBlocks = pkgBlocks[1:]
	}

	// 清空全局包列表
	allDiscoveredPackages = make([]*pkg.Metadata, 0)

	// 创建主包对象
	pkgInfo := &pkg.Pkg{
		Metadata: &pkg.Metadata{
			Lifecycle: pkg.InstalledLifecycle,
		},
		Depends: &[]pkg.Depend{},
	}

	// 是否设置了主包
	hasSetMainPackage := false

	// 依赖关系数组
	var allDependencies []pkg.Depend

	// 重置已处理的包名映射
	processedPkgMap := make(map[string]bool)

	// 解析包信息块的计数器
	parsedCount := 0
	skippedCount := 0

	// 处理每个软件包信息块
	for _, block := range pkgBlocks {
		if strings.TrimSpace(block) == "" {
			continue
		}

		// 解析包信息
		info := make(map[string]string)
		var lastKey string
		var pkgName string

		lines := strings.Split(block, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}

			if strings.HasPrefix(line, " ") {
				// 多行字段的续行
				if lastKey != "" {
					info[lastKey] += "\n" + strings.TrimSpace(line)
				}
				continue
			}

			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			info[key] = value
			lastKey = key

			// 特别记录包名
			if key == "Package" {
				pkgName = value
			}
		}

		// 检查是否已经处理过这个包
		if processedPkgMap[pkgName] {
			skippedCount++
			continue
		}

		// 检查是否已安装的状态
		status, ok := info["Status"]
		if !ok {
			skippedCount++
			continue
		}

		if !strings.Contains(status, "installed") ||
			strings.Contains(status, "not-installed") ||
			strings.Contains(status, "config-files") {
			skippedCount++
			continue
		}

		// 处理有包名称的条目
		if pkgName != "" {
			// 标记为已处理
			processedPkgMap[pkgName] = true

			// 创建元数据
			metadata := &pkg.Metadata{
				Name:         pkgName,
				Version:      info["Version"],
				Architecture: info["Architecture"],
				Description:  info["Description"],
				Maintainer:   info["Maintainer"],
				Section:      info["Section"],
				Priority:     info["Priority"],
				SourcePkg:    info["Source"],
				Lifecycle:    pkg.InstalledLifecycle,
				License:      []string{}, // 初始化为空数组
			}

			// 尝试从copyright文件获取许可证信息
			if copyrightDir != "" {
				// 直接检查每个包对应的copyright文件
				copyrightFilePath := filepath.Join(copyrightDir, pkgName)
				if _, err := os.Stat(copyrightFilePath); err == nil {
					licenseInfo, err := parseLicensesFromCopyright(copyrightFilePath)
					if err == nil && len(licenseInfo) > 0 {
						metadata.License = licenseInfo
					}
				} else {
					// 如果无法找到copyright文件，尝试寻找类似名称的目录
					copyrightDirEntries, _ := os.ReadDir(copyrightDir)
					for _, entry := range copyrightDirEntries {
						if strings.Contains(entry.Name(), pkgName) {
							alternativePath := filepath.Join(copyrightDir, entry.Name())
							if licenseInfo, err := parseLicensesFromCopyright(alternativePath); err == nil && len(licenseInfo) > 0 {
								metadata.License = licenseInfo
								break
							}
						}
					}
				}
			}

			// 添加Homepage作为URL
			if homepage, ok := info["Homepage"]; ok && homepage != "" {
				metadata.Url = strings.TrimSpace(homepage)
			}

			// 生成CPE
			metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", pkgName, metadata.Version)

			// 生成PURL
			metadata.PURL = fmt.Sprintf("pkg:deb/%s@%s?arch=%s&distro=%s", pkgName, metadata.Version, metadata.Architecture, distro)

			// 生成BOMRef和包ID
			packageId := generatePackageId(pkgName, metadata.Version)
			metadata.BomRef = fmt.Sprintf("pkg:deb/%s@%s?arch=%s&distro=%s&package-id=%s",
				pkgName, metadata.Version, metadata.Architecture, distro, packageId)

			// 处理Provides字段
			var packageProvides []string
			if provides, ok := info["Provides"]; ok && provides != "" {
				// 解析Provides字段
				providesList := strings.Split(provides, ",")
				for _, provide := range providesList {
					provide = strings.TrimSpace(provide)
					if provide != "" {
						// 处理可能的版本限定等
						provideParts := strings.Split(provide, " ")
						packageProvides = append(packageProvides, provideParts[0])
					}
				}
			}

			// 提取依赖信息
			var packageDepends []string
			if depends, ok := info["Depends"]; ok && depends != "" {
				// 解析Depends字段，格式通常为: pkg1, pkg2 (>= 1.0) | pkg3, ...
				deps := strings.Split(depends, ",")
				for _, dep := range deps {
					dep = strings.TrimSpace(dep)
					if dep == "" {
						continue
					}

					// 提取基本包名（去除版本和其他条件）
					depParts := strings.Split(dep, " ")
					if len(depParts) > 0 {
						// 处理可选依赖 (包含 | 符号)
						alternatives := strings.Split(depParts[0], "|")
						for _, alt := range alternatives {
							altName := strings.TrimSpace(alt)
							if altName != "" {
								packageDepends = append(packageDepends, altName)
							}
						}
					}
				}
			}

			// 将包添加到全局列表中
			parsedCount++
			allDiscoveredPackages = append(allDiscoveredPackages, metadata)

			// 保存包的provides和depends信息到全局映射
			pkgInfoMap := &PackageInfo{
				BOMRef:   metadata.BomRef,
				Name:     metadata.Name,
				Provides: append([]string{metadata.Name}, packageProvides...),
				Depends:  packageDepends,
			}
			globalPackageInfoMap[metadata.Name] = pkgInfoMap

			// 如果尚未设置主包，设置当前包为主包
			if !hasSetMainPackage {
				pkgInfo.Metadata = metadata
				hasSetMainPackage = true
			} else {
				// 添加为依赖
				depend := pkg.Depend{
					Metadata:      *metadata,
					DebDependType: "normal",
				}
				allDependencies = append(allDependencies, depend)
			}
		}
	}

	// 添加所有依赖关系
	if len(allDependencies) > 0 {
		*pkgInfo.Depends = append(*pkgInfo.Depends, allDependencies...)
	}

	return pkgInfo, nil
}

// parseRpmSqlite 解析RPM数据库sqlite文件
func parseRpmSqlite(filePath string, imagePath string) (*pkg.Pkg, error) {
	// 显示进度-开始解析SQLite数据库
	showProgress(40, "开始解析RPM数据库...")

	// 尝试使用SQLite方式打开
	db, err := sql.Open("sqlite3", filePath)
	if err != nil {
		return nil, fmt.Errorf("\nSQLite访问失败: %v", err)
	}

	// 检查连接是否真的成功
	err = db.Ping()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("\nSQLite连接失败: %v", err)
	}

	defer db.Close()

	// 显示进度-数据库连接成功
	showProgress(45)

	// 获取系统信息用于生成 PURL
	var namespace, distro string

	// 尝试获取系统信息
	osReleaseOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "cat", "/etc/os-release")
	if err == nil {
		namespace, distro = parseOsInfo(osReleaseOutput)
	} else {
		// 如果获取失败，使用默认值
		namespace = "fedora"
		distro = "fedora"
	}

	// 显示进度-获取系统信息完成
	showProgress(50)

	pkgInfo := &pkg.Pkg{
		Metadata: &pkg.Metadata{
			Lifecycle: pkg.InstalledLifecycle,
		},
		Depends: &[]pkg.Depend{},
	}

	// 清空全局包列表
	allDiscoveredPackages = make([]*pkg.Metadata, 0)

	// 查询所有已安装的包
	rows, err := db.Query(`
        SELECT 
            name, 
            version, 
            release, 
            arch, 
            license, 
            summary, 
            description, 
            sourcerpm
        FROM packages
    `)
	if err != nil {
		// 如果查询失败，返回错误
		return nil, fmt.Errorf("\nSQLite查询失败: %v", err)
	}
	defer rows.Close()

	// 显示进度-开始处理包查询结果
	showProgress(55)

	// 处理查询结果
	var processedPackages int
	var packagesWithLicense int
	var packagesList []*pkg.Metadata

	// 计算每10%的包的进度
	progressStep := 5 // 处理包的总计进度20% (从55%到75%)

	for rows.Next() {
		var entry struct {
			Name        string
			Version     string
			Release     string
			Arch        string
			License     string
			Summary     string
			Description string
			SourceRpm   string
		}

		if err := rows.Scan(&entry.Name, &entry.Version, &entry.Release, &entry.Arch,
			&entry.License, &entry.Summary, &entry.Description, &entry.SourceRpm); err != nil {
			continue
		}

		processedPackages++

		metadata := &pkg.Metadata{
			Name:         entry.Name,
			Version:      entry.Version,
			Release:      entry.Release,
			Architecture: entry.Arch,
			Description:  entry.Summary,
			SourcePkg:    entry.SourceRpm,
		}

		// 添加许可证信息
		if entry.License != "" {
			metadata.License = []string{entry.License}
			packagesWithLicense++
		} else {
			metadata.License = []string{}
		}

		// 生成CPE
		metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*",
			metadata.Name, metadata.Version)

		// 生成PURL
		metadata.PURL = fmt.Sprintf("pkg:rpm/%s/%s@%s?arch=%s&release=%s&distro=%s",
			namespace, metadata.Name, metadata.Version, metadata.Architecture,
			metadata.Release, distro)

		// 生成BOMRef
		packageId := generatePackageId(metadata.Name, metadata.Version)
		metadata.BomRef = fmt.Sprintf("pkg:rpm/%s/%s@%s?arch=%s&distro=%s&upstream=%s-%s.src.rpm&package-id=%s",
			namespace, metadata.Name, metadata.Version, metadata.Architecture,
			distro, metadata.Name, metadata.Version, packageId)

		// 将包添加到列表
		packagesList = append(packagesList, metadata)

		// 每处理100个包更新一次进度
		if processedPackages%100 == 0 {
			// 计算处理进度
			currentProgress := 55 + int(float64(processedPackages)/1000.0*float64(progressStep))
			// 确保不超过上限
			if currentProgress > 75 {
				currentProgress = 75
			}
			showProgress(currentProgress)
		}
	}

	// 处理完所有包
	showProgress(75)

	// 将所有处理好的包添加到全局列表
	allDiscoveredPackages = append(allDiscoveredPackages, packagesList...)

	// 如果有包，设置第一个为主包
	if len(packagesList) > 0 {
		pkgInfo.Metadata = packagesList[0]
	}

	if err = rows.Err(); err != nil {
		if !quietMode {
			fmt.Printf("遍历行时出错: %v\n", err)
		}
	}

	// 处理依赖关系
	showProgress(80)

	// 完成处理
	showProgress(85)

	return pkgInfo, nil
}

// parseRpmDb 解析RPM数据库文件
func parseRpmDb(filePath string, imagePath string) (*pkg.Pkg, error) {
	// 使用rpmdb库打开包数据库
	db, err := rpmdb.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("\nAn error occurred while parsing the RPM database information:%v", err)
	}
	defer db.Close()

	packages, err := db.ListPackages()
	if err != nil {
		return nil, fmt.Errorf("\nAn error occurred while parsing the RPM database package list information: %v", err)
	}

	// 获取系统信息用于生成 PURL
	var namespace, distro string

	// 尝试获取系统信息
	osReleaseOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "cat", "/etc/os-release")
	if err == nil {
		namespace, distro = parseOsInfo(osReleaseOutput)
	} else {
		// 如果获取失败，使用默认值
		namespace = "linux"
		distro = "unknown"
	}

	pkgInfo := &pkg.Pkg{
		Metadata: &pkg.Metadata{
			Lifecycle: pkg.InstalledLifecycle,
		},
		Depends: &[]pkg.Depend{},
	}

	// 创建一个包集合来存储所有找到的包
	allPackages := []*pkg.Metadata{}

	// 存储每个包的提供和依赖信息
	packageInfoMap := make(map[string]*PackageInfo)

	var processedPackages int
	var packagesWithLicense int

	// 重置已处理的包名映射
	processedPkgMap := make(map[string]bool)

	// 处理所有的二进制包
	for _, entry := range packages {
		if entry == nil {
			continue
		}

		// 标记此包已处理，避免重复处理
		processedPkgMap[entry.Name] = true

		processedPackages++

		metadata := &pkg.Metadata{
			Name:         entry.Name,
			Version:      entry.Version,
			Release:      entry.Release,
			Architecture: entry.Arch,
			Description:  entry.Summary,
			Packager:     entry.Vendor,
			BuildTime:    time.Unix(int64(entry.InstallTime), 0).Format("2006-01-02 15:04:05"),
			BuildHost:    "",              // RPM包中可能没有BuildHost字段
			SourcePkg:    entry.SourceRpm, // 设置源码包信息
		}

		// 添加许可证信息
		if entry.License != "" {
			metadata.License = []string{entry.License}
			packagesWithLicense++
		} else {
			fmt.Printf("Warning: The package %s does not have license information.\n", entry.Name)
		}

		// 生成 CPE
		metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", metadata.Name, metadata.Version)

		// 生成 PURL
		purl := pkg.RpmPackageURL(packageurl.TypeRPM, namespace, entry.Name, entry.Arch, entry.SourceRpm, entry.Version, entry.Release, distro)
		metadata.PURL = purl

		// 生成 BOMRef
		bomRef, err := pkg.GetBomRef(purl, struct {
			Name         string
			Version      string
			Architecture string
			timestamp    time.Time
		}{
			Name:         entry.Name,
			Version:      entry.Version,
			Architecture: entry.Arch,
			timestamp:    time.Now(),
		}, "package-id")
		if err != nil {
			return nil, fmt.Errorf("\n生成BOMRef失败: %v", err)
		}
		metadata.BomRef = bomRef

		// 将包添加到集合
		allPackages = append(allPackages, metadata)

		// 保存包的provides和depends信息
		pkgInfo := &PackageInfo{
			BOMRef:   metadata.BomRef,
			Name:     metadata.Name,
			Provides: []string{metadata.Name}, // 包自身就是一个provide
			Depends:  []string{},
		}

		// 添加包的provides
		for _, provide := range entry.Provides {
			// 根据RPM库的类型确定处理方式
			if provide != "" {
				pkgInfo.Provides = append(pkgInfo.Provides, provide)
			}
		}

		// 添加包的depends
		for _, require := range entry.Requires {
			// 根据RPM库的类型确定处理方式
			if require != "" {
				pkgInfo.Depends = append(pkgInfo.Depends, require)
			}
		}

		// 保存到映射
		packageInfoMap[metadata.Name] = pkgInfo
		globalPackageInfoMap[metadata.Name] = pkgInfo // 同时保存到全局映射

	}

	// 设置所有包，而不仅仅是第一个
	if len(allPackages) > 0 {
		pkgInfo.Metadata = allPackages[0]

		// 创建存储依赖关系的切片
		depends := []pkg.Depend{}

		// 从第二个包开始，将所有包作为依赖添加
		for _, metadata := range allPackages[1:] {
			depend := pkg.Depend{
				Metadata: *metadata,
			}
			depends = append(depends, depend)
		}

		// 更新依赖关系
		if len(depends) > 0 {
			*pkgInfo.Depends = append(*pkgInfo.Depends, depends...)
		}
	}

	// 使用全局变量保存所有包
	allDiscoveredPackages = allPackages

	return pkgInfo, nil
}

// parseOsInfo 解析系统信息
func parseOsInfo(osRelease string) (namespace string, distro string) {
	lines := strings.Split(osRelease, "\n")
	var id, version string

	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		}
	}

	namespace = strings.ToLower(id)
	distro = fmt.Sprintf("%s-%s", namespace, version)
	return
}

// parseKernelInfo 获取Linux内核信息
func parseKernelInfo(imagePath string) (*pkg.LinuxKernel, error) {
	kernel := &pkg.LinuxKernel{}

	// 获取内核版本
	versionOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "uname", "-r")
	if err != nil {
		// 如果无法获取内核版本，使用默认值
		kernel.Version = "unknown"
		kernel.Name = "linux-unknown"
	} else {
		kernel.Version = strings.TrimSpace(versionOutput)
		kernel.Name = "linux-" + kernel.Version
	}

	// 获取架构信息
	archOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "uname", "-m")
	if err != nil {
		// 如果无法获取架构信息，使用默认值
		kernel.Architecture = "unknown"
	} else {
		kernel.Architecture = strings.TrimSpace(archOutput)
	}

	// 获取编译时间和编译器信息
	versionInfo, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "cat", "/proc/version")
	if err == nil {
		// 解析编译器信息
		if compilerIdx := strings.Index(versionInfo, "gcc version"); compilerIdx != -1 {
			compilerEnd := strings.Index(versionInfo[compilerIdx:], ")")
			if compilerEnd != -1 {
				kernel.Compiler = strings.TrimSpace(versionInfo[compilerIdx : compilerIdx+compilerEnd+1])
			}
		}
	}

	// 获取编译时间
	buildTimeOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "uname", "-v")
	if err == nil {
		kernel.BuildTime = parseBuildTime(buildTimeOutput)
	} else {
		kernel.BuildTime = time.Now().Format("2006-01-02 15:04:05")
	}

	// 生成 bomRef
	kernel.BomRef = fmt.Sprintf("pkg:kernel/linux@%s?arch=%s", kernel.Version, kernel.Architecture)

	return kernel, nil
}

// parseBuildTime 解析编译时间字符串
func parseBuildTime(timeStr string) string {
	timeStr = strings.TrimSpace(timeStr)

	// 尝试提取日期时间部分
	parts := strings.Fields(timeStr)
	if len(parts) >= 7 {
		// 组合日期时间字符串
		dateStr := fmt.Sprintf("%s %s %s %s %s", parts[2], parts[3], parts[4], parts[5], parts[6])

		// 尝试解析时间
		t, err := time.Parse("Jan 2 15:04:05 MST 2006", dateStr)
		if err == nil {
			return t.Format("2006-01-02 15:04:05")
		}
	}

	// 如果解析失败，返回原始字符串
	return timeStr
}

// convertToSBOMFormat 将扫描结果转换为SBOM格式
func convertToSBOMFormat(result *ScanResult) *outputSBOM {
	mainBomRef, err := _package.IDByHash(result)
	if err != nil {
		fmt.Println("mainBomRef获取错误", err)
	}
	// 创建SBOM输出结构
	sbom := &outputSBOM{
		Schema:       "http://cyclonedx.org/schema/bom-1.6.schema.json",
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: uuid.New().URN(),
		Version:      1,
		MainMetadata: MainMetadata{
			CraeateTime: time.Now().Format(time.RFC3339),
			Tools: ToolsInfo{
				Components: []ToolComponent{
					{
						Type:    string(cyclonedx.ComponentTypeApplication),
						Name:    "SLP",
						Version: "1.0",
					},
				},
			},
			Component: ComponentOutput{
				BOMRef: mainBomRef,
				Name:   result.OsType,
				Type:   string(cyclonedx.ComponentTypeContainer),
			},
		},
		Components:   []ComponentOutput{},
		Dependencies: []DependencyOutput{},
	}

	// 添加内核组件
	if result.Kernel != nil {
		component := ComponentOutput{
			BOMRef:       fmt.Sprintf("pkg:kernel/linux@%s?arch=%s", result.Kernel.Version, result.Kernel.Architecture),
			Name:         fmt.Sprintf("linux-%s", result.Kernel.Version),
			Type:         "linux_kernel",
			Version:      result.Kernel.Version,
			Architecture: result.Kernel.Architecture,
			BuildTime:    parseBuildTime(result.Kernel.BuildTime),
		}
		sbom.Components = append(sbom.Components, component)
	}

	// 处理所有软件包 - 先使用AllPackages字段
	if len(result.AllPackages) > 0 {
		for _, metadata := range result.AllPackages {
			component := createPackageComponent(metadata)
			sbom.Components = append(sbom.Components, component)
		}
	} else if result.Packages != nil && result.Packages.Metadata != nil {
		// 备用：使用packages.Metadata
		component := createPackageComponent(result.Packages.Metadata)
		sbom.Components = append(sbom.Components, component)

		// 处理依赖
		if result.Packages.Depends != nil {
			for _, dep := range *result.Packages.Depends {
				component := createDependencyComponent(&dep)
				sbom.Components = append(sbom.Components, component)
			}
		}
	}

	// 处理包之间的依赖关系
	if len(result.PackageMap) > 0 {
		processDependencies(sbom, result.PackageMap)
	}

	return sbom
}

// processDependencies 处理依赖关系并添加到SBOM中
func processDependencies(sbom *outputSBOM, pkgInfoMap map[string]*PackageInfo) {
	// 建立provides到提供者的映射
	providesMap := make(map[string][]string) // 功能名称 -> 提供该功能的包的BOMRef列表

	// 首先收集所有provides信息
	for _, pkgInfo := range pkgInfoMap {
		for _, provide := range pkgInfo.Provides {
			providesMap[provide] = append(providesMap[provide], pkgInfo.BOMRef)
		}

		// 对于Debian/Ubuntu包，包名本身也是一种"提供"
		providesMap[pkgInfo.Name] = append(providesMap[pkgInfo.Name], pkgInfo.BOMRef)
	}

	// 处理每个包的依赖
	dependencyAdded := make(map[string]bool) // 避免重复添加依赖

	for _, pkgInfo := range pkgInfoMap {
		// 创建依赖集合
		var dependsOn []string

		// 处理每个依赖
		for _, depend := range pkgInfo.Depends {
			// 查找提供该依赖的包
			if providers, ok := providesMap[depend]; ok {
				for _, provider := range providers {
					if provider != pkgInfo.BOMRef { // 避免自依赖
						dependsOn = append(dependsOn, provider)
					}
				}
			}
		}

		// 如果有依赖，添加到SBOM
		if len(dependsOn) > 0 {
			// 去重
			uniqueDependsOn := make(map[string]bool)
			for _, dep := range dependsOn {
				uniqueDependsOn[dep] = true
			}

			// 转换为列表
			uniqueDependsList := []string{}
			for dep := range uniqueDependsOn {
				uniqueDependsList = append(uniqueDependsList, dep)
			}

			// 添加依赖关系，使用结构体确保ref字段在dependsOn之前
			dependency := DependencyOutput{
				Ref:       pkgInfo.BOMRef,
				DependsOn: uniqueDependsList,
			}

			// 避免重复添加
			dependencyKey := pkgInfo.BOMRef
			if !dependencyAdded[dependencyKey] {
				sbom.Dependencies = append(sbom.Dependencies, dependency)
				dependencyAdded[dependencyKey] = true
			}
		}
	}
}

// formatLicenses 格式化许可证信息，应用SPDX格式化
func formatLicenses(licenses []string) []map[string]interface{} {
	if len(licenses) == 0 {
		return nil
	}

	// 规范化所有许可证
	var normalizedLicenses []string
	for _, license := range licenses {
		license = strings.TrimSpace(license)
		if license == "" {
			continue
		}
		normalizedLicense := normalizeLicenseId(license)
		if normalizedLicense != "" {
			normalizedLicenses = append(normalizedLicenses, normalizedLicense)
		}
	}

	// 如果没有有效的许可证，返回nil
	if len(normalizedLicenses) == 0 {
		return nil
	}

	// 连接所有许可证为一个字符串，用" AND "连接
	combinedLicense := strings.Join(normalizedLicenses, " AND ")

	// 返回单个许可证对象
	return []map[string]interface{}{
		{
			"license": map[string]string{
				"name": combinedLicense,
			},
		},
	}
}

// normalizeLicenseId 规范化许可证ID到SPDX格式
func normalizeLicenseId(license string) string {
	// 规范化常见的非标准许可证标识符到SPDX格式
	licenseMap := map[string]string{
		"GPL-2":         "GPL-2.0-only",
		"GPL-2+":        "GPL-2.0-or-later",
		"GPL-3":         "GPL-3.0-only",
		"GPL-3+":        "GPL-3.0-or-later",
		"LGPL-2":        "LGPL-2.0-only",
		"LGPL-2+":       "LGPL-2.0-or-later",
		"LGPL-3":        "LGPL-3.0-only",
		"LGPL-3+":       "LGPL-3.0-or-later",
		"BSD-3-clause":  "BSD-3-Clause",
		"BSD-2-clause":  "BSD-2-Clause",
		"MIT":           "MIT",
		"Apache-2.0":    "Apache-2.0",
		"MPL-2.0":       "MPL-2.0",
		"Expat":         "MIT",
		"Public Domain": "CC0-1.0",
		"GPLv2":         "GPL-2.0-only",
		"GPLv2+":        "GPL-2.0-or-later",
		"GPLv3":         "GPL-3.0-only",
		"GPLv3+":        "GPL-3.0-or-later",
		"LGPLv2":        "LGPL-2.0-only",
		"LGPLv2+":       "LGPL-2.0-or-later",
		"LGPLv3":        "LGPL-3.0-only",
		"LGPLv3+":       "LGPL-3.0-or-later",
		"BSD":           "BSD-3-Clause",
		"ASL 2.0":       "Apache-2.0",
		"zlib":          "Zlib",
		"Boost":         "BSL-1.0",
		"Mulan PSL v2":  "MulanPSL-2.0",
	}

	// 处理常见组合格式
	if strings.Contains(license, " and ") {
		parts := strings.Split(license, " and ")
		var normalizedParts []string
		for _, part := range parts {
			normalized := normalizeLicenseId(strings.TrimSpace(part))
			if normalized != "" {
				normalizedParts = append(normalizedParts, normalized)
			} else {
				normalizedParts = append(normalizedParts, strings.TrimSpace(part))
			}
		}
		return strings.Join(normalizedParts, " AND ")
	} else if strings.Contains(license, " or ") {
		parts := strings.Split(license, " or ")
		var normalizedParts []string
		for _, part := range parts {
			normalized := normalizeLicenseId(strings.TrimSpace(part))
			if normalized != "" {
				normalizedParts = append(normalizedParts, normalized)
			} else {
				normalizedParts = append(normalizedParts, strings.TrimSpace(part))
			}
		}
		return strings.Join(normalizedParts, " OR ")
	}

	// 直接映射
	if spdxId, ok := licenseMap[license]; ok {
		return spdxId
	}

	// 如果是SPDX标准格式，直接返回
	if isSPDXFormat(license) {
		return license
	}

	return license
}

// isSPDXFormat 检查许可证ID是否已经是SPDX格式
func isSPDXFormat(license string) bool {
	// 简单检查是否符合SPDX常见的格式模式
	spdxPatterns := []string{
		"^[A-Z]+-[0-9]+\\.[0-9]+-only$",
		"^[A-Z]+-[0-9]+\\.[0-9]+-or-later$",
		"^[A-Z]+-[0-9]+\\.[0-9]+$",
		"^[A-Z]+-[0-9]+-Clause$",
	}

	for _, pattern := range spdxPatterns {
		matched, _ := regexp.MatchString(pattern, license)
		if matched {
			return true
		}
	}

	return false
}

// createPackageComponent 从软件包元数据创建组件
func createPackageComponent(metadata *pkg.Metadata) ComponentOutput {
	// 创建基本组件信息
	component := ComponentOutput{
		BOMRef:       metadata.BomRef,
		Name:         metadata.Name,
		Type:         "library",
		Version:      metadata.Version,
		Architecture: metadata.Architecture,
		CPE:          metadata.CPE,
	}

	// 添加PURL
	if metadata.PURL != "" {
		component.PURL = metadata.PURL
	}

	// 添加许可证信息 - 使用新的格式化函数
	if len(metadata.License) > 0 {
		component.Licenses = formatLicenses(metadata.License)
	}

	// 添加外部引用（URL）
	if metadata.Url != "" {
		component.ExternalReferences = []map[string]string{
			{
				"url":  metadata.Url,
				"type": "website",
			},
		}
	}

	// 获取元数据属性
	properties := getPropertiesFromMetadata(metadata)

	// 只有在存在属性时才添加properties字段
	if len(properties) > 0 {
		component.Properties = properties
	}

	return component
}

// 新增函数：从Metadata生成属性列表，避免重复添加
func getPropertiesFromMetadata(metadata *pkg.Metadata) []map[string]string {
	properties := []map[string]string{}

	// 架构信息
	if metadata.Architecture != "" {
		properties = append(properties, map[string]string{
			"name":  "architecture",
			"value": metadata.Architecture,
		})
	}

	// 维护者信息
	if metadata.Maintainer != "" {
		properties = append(properties, map[string]string{
			"name":  "maintainer",
			"value": metadata.Maintainer,
		})
	}

	// 分类信息
	if metadata.Section != "" {
		properties = append(properties, map[string]string{
			"name":  "section",
			"value": metadata.Section,
		})
	}

	// 优先级信息
	if metadata.Priority != "" {
		properties = append(properties, map[string]string{
			"name":  "priority",
			"value": metadata.Priority,
		})
	}

	// 源码包信息
	if metadata.SourcePkg != "" {
		properties = append(properties, map[string]string{
			"name":  "sourcePkg",
			"value": metadata.SourcePkg,
		})
	}

	// 发布版本信息
	if metadata.Release != "" {
		properties = append(properties, map[string]string{
			"name":  "release",
			"value": metadata.Release,
		})
	}

	// 打包者信息
	if metadata.Packager != "" {
		properties = append(properties, map[string]string{
			"name":  "packager",
			"value": metadata.Packager,
		})
	}

	// 构建时间
	if metadata.BuildTime != "" {
		properties = append(properties, map[string]string{
			"name":  "buildTime",
			"value": metadata.BuildTime,
		})
	}

	// 构建主机
	if metadata.BuildHost != "" {
		properties = append(properties, map[string]string{
			"name":  "buildHost",
			"value": metadata.BuildHost,
		})
	}

	return properties
}

// createDependencyComponent 从依赖项创建组件
func createDependencyComponent(dep *pkg.Depend) ComponentOutput {
	// 创建依赖组件
	depComponent := ComponentOutput{
		BOMRef:  dep.Metadata.BomRef,
		Name:    dep.Metadata.Name,
		PURL:    dep.Metadata.PURL,
		Type:    string(cyclonedx.ComponentTypeLibrary), // 使用标准类型常量
		Version: dep.Metadata.Version,
	}

	// 添加CPE（如果有）
	if dep.Metadata.CPE != "" {
		depComponent.CPE = dep.Metadata.CPE
	}

	// 添加许可证信息 - 使用新的格式化函数
	if len(dep.Metadata.License) > 0 {
		depComponent.Licenses = formatLicenses(dep.Metadata.License)
	}

	// 添加外部引用（URL）
	if dep.Metadata.Url != "" {
		depComponent.ExternalReferences = []map[string]string{
			{
				"url":  dep.Metadata.Url,
				"type": "website",
			},
		}
	}

	// 获取基本属性
	props := getPropertiesFromMetadata(&dep.Metadata)

	// 添加依赖特定属性
	if dep.RpmRequire != "" {
		props = append(props, map[string]string{
			"name":  "dependencyType",
			"value": "rpm-require",
		})
		props = append(props, map[string]string{
			"name":  "dependencyFlags",
			"value": dep.RpmRequire,
		})
	} else if dep.DebDependType != "" {
		props = append(props, map[string]string{
			"name":  "dependencyType",
			"value": dep.DebDependType,
		})
	}

	// 只有在有属性时才添加属性字段
	if len(props) > 0 {
		depComponent.Properties = props
	}

	return depComponent
}

// 生成一个简单的包ID
func generatePackageId(name string, version string) string {
	h := sha1.New()
	io.WriteString(h, name+version)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// 从scan/source/parse_deb_copyright.go文件复制的函数，用于解析copyright文件获取许可证信息
func parseLicensesFromCopyright(filePath string) ([]string, error) {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("\nfailed to open file: %w", err)
	}
	defer file.Close()

	// 用于存储找到的许可证信息
	licenseMap := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 查找以"License:"开头的行
		if strings.HasPrefix(line, "License:") {
			// 提取许可证名称
			licenseName := strings.TrimSpace(strings.TrimPrefix(line, "License:"))

			// 如果许可证名称非空且尚未添加，则添加到集合中（去重）
			if licenseName != "" && !licenseMap[licenseName] {
				// 去除许可证名称中可能的注释或额外信息
				if idx := strings.Index(licenseName, " "); idx > 0 {
					// 只保留第一部分作为许可证标识符
					licenseType := licenseName[:idx]
					// 一些常见的许可证简写
					switch licenseType {
					case "GPL-2", "GPL-2+", "GPL-3", "GPL-3+", "LGPL-2", "LGPL-2+", "LGPL-3", "LGPL-3+",
						"BSD-3-clause", "BSD-2-clause", "MIT", "Apache-2.0", "MPL-2.0", "Expat":
						licenseMap[licenseType] = true
					default:
						// 如果不是常见的简写，保留完整的许可证标识符
						licenseMap[licenseName] = true
					}
				} else {
					licenseMap[licenseName] = true
				}
			}
		}

		// 查找common-licenses引用
		if strings.Contains(line, "/usr/share/common-licenses/") {
			commonLicensePattern := regexp.MustCompile(`/usr/share/common-licenses/(?P<license>[0-9A-Za-z_.\-]+)`)
			matches := commonLicensePattern.FindStringSubmatch(line)
			if len(matches) > 1 {
				licenseName := matches[1]
				licenseMap[licenseName] = true
			}
		}
	}

	// 检查扫描错误
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("\nerror reading Copyright file: %v", err)
	}

	// 将许可证集合转换为切片
	var licenses []string
	for license := range licenseMap {
		licenses = append(licenses, license)
	}

	// 排序结果，使输出稳定
	sort.Strings(licenses)

	return licenses, nil
}

// parseRpmViaDocker 使用Docker命令获取RPM包信息
func parseRpmViaDocker(imagePath string) (*pkg.Pkg, error) {
	// 创建包对象
	pkgInfo := &pkg.Pkg{
		Metadata: &pkg.Metadata{
			Lifecycle: pkg.InstalledLifecycle,
		},
		Depends: &[]pkg.Depend{},
	}

	// 显示进度-开始解析
	showProgress(30)

	// 获取系统信息用于生成 PURL
	var namespace, distro string

	// 尝试获取系统信息
	osReleaseOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "cat", "/etc/os-release")
	if err == nil {
		namespace, distro = parseOsInfo(osReleaseOutput)
	} else {
		// 如果获取失败，使用默认值
		namespace = "fedora"
		distro = "fedora"
	}

	// 显示进度-获取系统信息完成
	showProgress(35)

	// 获取所有已安装的包名称
	packagesOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "rpm", "-qa", "--queryformat", "%{NAME}\\n")
	if err != nil {
		return nil, fmt.Errorf("\n获取包列表失败: %v", err)
	}

	// 清理和分割输出
	packages := strings.Split(strings.TrimSpace(packagesOutput), "\n")

	// 清空全局包列表和映射
	allDiscoveredPackages = make([]*pkg.Metadata, 0)
	globalPackageInfoMap = make(map[string]*PackageInfo)

	// 显示进度-获取包列表完成
	showProgress(40)

	// 更新总体进度
	showProgress(45)

	// 依赖关系数组
	var allDependencies []pkg.Depend

	// 是否设置了主包
	hasSetMainPackage := false

	// 已处理的包名，避免重复
	processedPackages := make(map[string]bool)

	// 批量获取包的信息和依赖关系
	totalPackages := len(packages)

	// 计算每个包的进度增量 - 处理包信息总共占据45%的进度(从45%到90%)
	packageIncrement := 45.0 / float64(totalPackages)

	for i, pkgName := range packages {
		if pkgName == "" || processedPackages[pkgName] {
			continue
		}

		processedPackages[pkgName] = true

		// 更新进度 - 更加细粒度的进度展示
		currentProgress := 45 + int(float64(i)*packageIncrement)
		showProgress(currentProgress)

		// 获取包详细信息
		infoOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "rpm", "-qi", pkgName)
		if err != nil {
			continue
		}

		// 解析包信息
		metadata := parseRpmInfo(infoOutput)
		if metadata == nil {
			continue
		}

		// 获取源码包信息和URL在同一个命令中
		sourceRpmOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "rpm", "-q", "--qf", "%{SOURCERPM}\n%{URL}", pkgName)
		if err == nil && sourceRpmOutput != "" {
			lines := strings.Split(sourceRpmOutput, "\n")
			if len(lines) >= 1 && lines[0] != "" && lines[0] != "(none)" {
				metadata.SourcePkg = strings.TrimSpace(lines[0])
			}
			if len(lines) >= 2 && lines[1] != "" && lines[1] != "(none)" {
				metadata.Url = strings.TrimSpace(lines[1])
			}
		}

		// 使用正确的namespace和distro重新设置PURL和BOMRef
		metadata.PURL = fmt.Sprintf("pkg:rpm/%s/%s@%s?arch=%s&release=%s&distro=%s",
			namespace, metadata.Name, metadata.Version, metadata.Architecture,
			metadata.Release, distro)

		// 重新生成BomRef
		packageId := generatePackageId(metadata.Name, metadata.Version)
		metadata.BomRef = fmt.Sprintf("pkg:rpm/%s/%s@%s?arch=%s&distro=%s&upstream=%s-%s.src.rpm&package-id=%s",
			namespace, metadata.Name, metadata.Version, metadata.Architecture,
			distro, metadata.Name, metadata.Version, packageId)

		// 保存到全局列表
		allDiscoveredPackages = append(allDiscoveredPackages, metadata)

		// 获取所有包的完整依赖关系
		dependsOutput, err := scan_utils.RunCommand("docker", "run", "--rm", imagePath, "rpm", "-qR", pkgName)
		var depends []string
		if err == nil && dependsOutput != "" {
			// 解析依赖
			depends = parseRpmDependencies(dependsOutput)
		}

		// 添加到全局包信息映射
		packageInfo := &PackageInfo{
			BOMRef:   metadata.BomRef,
			Name:     metadata.Name,
			Depends:  depends,
			Provides: []string{metadata.Name}, // 简单处理，包名即为提供的功能
		}
		globalPackageInfoMap[metadata.Name] = packageInfo

		// 如果有依赖，创建依赖对象
		if len(depends) > 0 {
			depObj := pkg.Depend{
				Metadata: *metadata,
			}
			allDependencies = append(allDependencies, depObj)
		}

		// 如果还没有设置主包，则设置第一个找到的包为主包
		if !hasSetMainPackage {
			pkgInfo.Metadata = metadata
			hasSetMainPackage = true
		}
	}

	// 完成包处理
	showProgress(90)

	// 设置依赖关系
	*pkgInfo.Depends = allDependencies

	// 准备生成SBOM
	showProgress(95)

	return pkgInfo, nil
}

// parseRpmInfo 解析rpm -qi命令输出的包信息
func parseRpmInfo(infoOutput string) *pkg.Metadata {
	// 创建元数据对象
	metadata := &pkg.Metadata{
		Lifecycle: pkg.InstalledLifecycle,
		License:   []string{}, // 初始化为空数组
	}

	// 解析rpm -qi输出的每一行
	lines := strings.Split(infoOutput, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Name":
			metadata.Name = value
		case "Version":
			metadata.Version = value
		case "Release":
			metadata.Release = value
		case "Architecture":
			metadata.Architecture = value
		case "License":
			metadata.License = []string{value}
		case "Summary":
			metadata.Description = value
		case "Description":
			// 如果已有Summary，可以追加或替换
			if metadata.Description != "" {
				metadata.Description += "\n" + value
			} else {
				metadata.Description = value
			}
		}
	}

	// 必须有包名和版本
	if metadata.Name == "" || metadata.Version == "" {
		return nil
	}

	// 生成CPE
	metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*",
		metadata.Name, metadata.Version)

	return metadata
}

// parseRpmDependencies 解析rpm -qR命令输出的依赖关系
func parseRpmDependencies(dependsOutput string) []string {
	var depends []string

	// 解析每一行
	lines := strings.Split(dependsOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 提取基本包名（去除版本和其他条件）
		parts := strings.Fields(line)
		if len(parts) > 0 {
			// rpm依赖通常格式为：pkgname >= version
			// 或者 rpmlib(xxx) 形式的特殊依赖
			depName := parts[0]

			// 过滤掉rpmlib依赖和系统提供的特殊依赖
			if strings.HasPrefix(depName, "rpmlib(") ||
				strings.HasPrefix(depName, "/") ||
				strings.Contains(depName, "(") {
				continue
			}

			depends = append(depends, depName)
		}
	}

	return depends
}
