package image

import (
	"bytes"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	pkg "slp/package"
	scan_utils "slp/utils"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	_ "github.com/mattn/go-sqlite3"
	"github.com/package-url/packageurl-go"
)

// 添加自定义结构体用于确保输出的JSON字段顺序正确
type ComponentOutput struct {
	BOMRef       string                   `json:"bom-ref"`
	Name         string                   `json:"name"`
	PURL         string                   `json:"purl,omitempty"`
	Type         string                   `json:"type"`
	Version      string                   `json:"version"`
	CPE          string                   `json:"cpe,omitempty"`
	Architecture string                   `json:"architecture,omitempty"`
	Licenses     []map[string]interface{} `json:"licenses,omitempty"`
	Properties   []map[string]string      `json:"properties,omitempty"`
	// 内核专用字段
	BuildTime string `json:"buildTime,omitempty"`
}

// 依赖关系结构体，确保ref字段在dependsOn之前
type DependencyOutput struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// SBOM格式的输出结构
type outputSBOM struct {
	Components   []ComponentOutput  `json:"components"`
	Dependencies []DependencyOutput `json:"dependencies,omitempty"`
}

// ScanResult 存储扫描结果
type ScanResult struct {
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
)

func init() {
	// 初始化全局变量
	globalPackageInfoMap = make(map[string]*PackageInfo)
	allDiscoveredPackages = make([]*pkg.Metadata, 0)
}

func ParseImageFile(path string) error {
	// 检查 docker image 是否存在
	_, err := scan_utils.RunCommand("docker", "inspect", path)
	if err != nil {
		return fmt.Errorf("docker镜像不存在: %v", err)
	}

	// 创建临时目录用于保存数据库文件
	tmpDir, err := os.MkdirTemp("", "pkg_db_*")
	if err != nil {
		return fmt.Errorf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// 获取系统类型信息 - 直接使用docker run而不是在容器中执行
	osReleaseOutput, err := scan_utils.RunCommand("docker", "run", "--rm", path, "cat", "/etc/os-release")
	var osRelease string
	var osType string
	if err != nil {
		// 如果无法获取/etc/os-release，尝试其他方法
		fmt.Println("尝试获取/etc/os-release失败，尝试其他方法...")

		// 尝试redhat-release
		redhatOutput, redhatErr := scan_utils.RunCommand("docker", "run", "--rm", path, "cat", "/etc/redhat-release")
		if redhatErr == nil {
			osRelease = strings.ToLower(redhatOutput)
			if strings.Contains(osRelease, "fedora") {
				osType = "fedora"
			} else {
				osType = "rpm-based"
			}
		} else {
			// 尝试rpm命令
			_, rpmErr := scan_utils.RunCommand("docker", "run", "--rm", path, "rpm", "--version")
			if rpmErr == nil {
				// 如果有rpm命令，假设是rpm系统
				osRelease = "rpm-based"
				osType = "rpm-based"
			} else {
				// 尝试dpkg命令
				_, dpkgErr := scan_utils.RunCommand("docker", "run", "--rm", path, "dpkg", "--version")
				if dpkgErr == nil {
					// 如果有dpkg命令，假设是Debian/Ubuntu系统
					osRelease = "dpkg-based"
					osType = "debian"
				} else {
					return fmt.Errorf("无法确定镜像的操作系统类型")
				}
			}
		}
	} else {
		osRelease = strings.ToLower(osReleaseOutput)

		// 解析os-release获取发行版类型
		if strings.Contains(osRelease, "debian") {
			osType = "debian"
		} else if strings.Contains(osRelease, "ubuntu") {
			osType = "ubuntu"
		} else if strings.Contains(osRelease, "fedora") {
			osType = "fedora"
		} else if strings.Contains(osRelease, "openeuler") {
			osType = "openeuler"
		} else {
			// 如果无法确定，返回错误
			return fmt.Errorf("不支持的操作系统类型: %s", osRelease)
		}
	}

	// 打印获取到的系统信息
	fmt.Printf("检测到系统类型: %s\n", osType)

	var dbPath string
	var targetPath string

	// 根据发行版类型设置对应的数据库文件路径
	switch osType {
	case "debian", "ubuntu": // Debian/Ubuntu使用相同的路径
		dbPath = "/var/lib/dpkg/status"
		targetPath = filepath.Join(tmpDir, "dpkg-status")

		// 对于Ubuntu/Debian，用一个更宽松的安装状态判断条件
		fmt.Println("Debian/Ubuntu系统：使用dpkg status文件进行扫描")
	case "fedora": // Fedora
		dbPath = "/var/lib/rpm/rpmdb.sqlite"
		targetPath = filepath.Join(tmpDir, "rpmdb.sqlite")
	case "openeuler": // OpenEuler
		dbPath = "/var/lib/rpm/Packages.db"
		targetPath = filepath.Join(tmpDir, "Packages.db")
	default:
		return fmt.Errorf("不支持的操作系统类型: %s", osType)
	}

	fmt.Printf("使用数据库路径: %s\n", dbPath)

	// 创建一个临时容器用于文件复制
	containerID, err := createTempContainer(path)
	if err != nil {
		return fmt.Errorf("创建临时容器失败: %v", err)
	}
	defer func() {
		_, _ = scan_utils.RunCommand("docker", "rm", "-f", containerID)
	}()

	_, err = scan_utils.RunCommand("docker", "start", containerID)
	if err != nil {
		return fmt.Errorf("启动容器失败: %v", err)
	}

	// 从容器中复制数据库文件
	_, err = scan_utils.RunCommand("docker", "cp", fmt.Sprintf("%s:%s", containerID, dbPath), targetPath)
	if err != nil {
		return fmt.Errorf("复制数据库文件失败: %v", err)
	}

	// 检查目标文件是否存在
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return fmt.Errorf("复制数据库文件后目标文件不存在: %s", targetPath)
	}

	// 获取内核信息
	kernelInfo, err := parseKernelInfo(path)
	if err != nil {
		return fmt.Errorf("获取内核信息失败: %v", err)
	}

	// 解析包管理数据库
	var pkgInfo *pkg.Pkg
	switch {
	case strings.HasSuffix(targetPath, "dpkg-status"):
		pkgInfo, err = parseDpkgStatus(targetPath)
	case strings.HasSuffix(targetPath, "rpmdb.sqlite"):
		pkgInfo, err = parseRpmSqlite(targetPath)
	case strings.HasSuffix(targetPath, "Packages.db"):
		pkgInfo, err = parseRpmDb(targetPath, path)
	}
	if err != nil {
		return fmt.Errorf("解析包管理数据库失败: %v", err)
	}

	// 创建扫描结果结构体
	scanResult := &ScanResult{
		Kernel:      kernelInfo,
		Packages:    pkgInfo,
		PackageMap:  globalPackageInfoMap,  // 使用全局变量
		AllPackages: allDiscoveredPackages, // 使用全局包数组
	}

	// 输出诊断信息，检查软件包数量
	fmt.Printf("==== 诊断信息 ====\n")
	fmt.Printf("全局包列表大小: %d\n", len(allDiscoveredPackages))
	fmt.Printf("全局映射大小: %d\n", len(globalPackageInfoMap))
	fmt.Printf("scanResult.AllPackages大小: %d\n", len(scanResult.AllPackages))
	fmt.Printf("===============\n")

	// 将结果转换为SBOM格式
	sbomOutput := convertToSBOMFormat(scanResult)

	// 使用自定义编码器来避免转义URL中的&字符
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false) // 这是关键设置：不转义HTML字符如&
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(sbomOutput); err != nil {
		return fmt.Errorf("转换JSON失败: %v", err)
	}

	// 正确定义输出文件名
	outputFilename := fmt.Sprintf("sbom_result_%s.json", time.Now().Format("20060102_150405"))

	// 创建输出文件
	err = os.WriteFile(outputFilename, buffer.Bytes(), 0644)
	if err != nil {
		return fmt.Errorf("写入结果文件失败: %v", err)
	}

	fmt.Printf("扫描结果已保存到: %s\n", outputFilename)
	return nil
}

// parseDpkgStatus 解析 Ubuntu/Debian 的 dpkg status 文件
func parseDpkgStatus(filePath string) (*pkg.Pkg, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取dpkg status文件失败: %v", err)
	}

	// 直接使用字符串读取，确保处理所有包
	contentStr := string(content)
	fmt.Printf("status文件大小: %d 字节\n", len(contentStr))

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

	fmt.Printf("找到 %d 个软件包信息块\n", len(pkgBlocks))

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

	// 已经处理过的包名，避免重复
	processedPackages := make(map[string]bool)

	// 在函数开始处添加
	defer func() {
		// 输出解析结果统计信息
		fmt.Printf("状态文件解析完成：\n")
		fmt.Printf("  - 发现包信息块: %d\n", len(pkgBlocks))
		fmt.Printf("  - 成功解析的包: %d\n", len(allDiscoveredPackages))
		fmt.Printf("  - 依赖关系数量: %d\n", len(allDependencies))
	}()

	// 在解析包信息块的循环中添加计数器
	totalBlocks := len(pkgBlocks)
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
		if processedPackages[pkgName] {
			fmt.Printf("警告: 重复的包 %s 被跳过\n", pkgName)
			skippedCount++
			continue
		}

		// 检查是否已安装的状态
		status, ok := info["Status"]
		if !ok {
			skippedCount++
			continue
		}

		// Debian/Ubuntu的status字段通常是"install ok installed"，但我们使用更宽松的条件
		// 只要字段中包含"installed"，并且不包含"not-installed"或"config-files"就视为已安装
		if !strings.Contains(status, "installed") ||
			strings.Contains(status, "not-installed") ||
			strings.Contains(status, "config-files") {
			skippedCount++
			continue
		}

		// 处理有包名称的条目
		if pkgName != "" {
			// 标记为已处理
			processedPackages[pkgName] = true

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
				License:      []string{}, // 设置为空数组，而不是尝试解析
			}

			// 生成CPE
			metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", pkgName, metadata.Version)

			// 生成PURL
			_, distro := parseOsInfo("/etc/os-release") // 从OS信息获取发行版
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

			// 添加到全局包信息映射
			packageInfo := &PackageInfo{
				BOMRef:   metadata.BomRef,
				Name:     pkgName,
				Depends:  packageDepends,  // 保存依赖列表
				Provides: packageProvides, // 保存提供列表
			}
			globalPackageInfoMap[pkgName] = packageInfo

			// 添加到全局包列表
			allDiscoveredPackages = append(allDiscoveredPackages, metadata)

			// 为此包创建依赖对象
			if len(packageDepends) > 0 {
				depObj := pkg.Depend{
					Metadata: pkg.Metadata{
						Name:    pkgName,
						Version: metadata.Version,
						BomRef:  metadata.BomRef,
					},
					DebDependType: "Depends",
				}
				allDependencies = append(allDependencies, depObj)
			}

			// 如果还没有设置主包，则设置第一个找到的包为主包
			if !hasSetMainPackage {
				pkgInfo.Metadata = metadata
				hasSetMainPackage = true
			}
		}

		// 在循环内部，处理每个块之后
		parsedCount++
		if parsedCount%100 == 0 || parsedCount == totalBlocks {
			fmt.Printf("  已处理 %d/%d 个块 (已解析: %d, 已跳过: %d)\n",
				parsedCount, totalBlocks, len(allDiscoveredPackages), skippedCount)
		}
	}

	// 在函数结束前，检查解析数量
	if len(allDiscoveredPackages) < 500 && totalBlocks > 500 {
		fmt.Printf("警告：解析的包数量(%d)远小于预期(%d)\n",
			len(allDiscoveredPackages), totalBlocks)
	}

	// 如果没有找到包，可能是解析问题
	if len(allDiscoveredPackages) == 0 {
		return nil, fmt.Errorf("没有解析到任何软件包信息")
	}

	// 设置依赖关系
	*pkgInfo.Depends = allDependencies

	fmt.Printf("成功解析了 %d 个 Debian 软件包, 包含 %d 个依赖关系\n",
		len(allDiscoveredPackages), len(allDependencies))

	return pkgInfo, nil
}

// 生成一个简单的包ID
func generatePackageId(name string, version string) string {
	h := sha1.New()
	io.WriteString(h, name+version)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// parseRpmSqlite 解析 Fedora 的 rpmdb.sqlite 文件
func parseRpmSqlite(filePath string) (*pkg.Pkg, error) {
	// 打开 SQLite 数据库
	db, err := sql.Open("sqlite3", filePath)
	if err != nil {
		return nil, fmt.Errorf("打开SQLite数据库失败: %v", err)
	}
	defer db.Close()

	fmt.Println("开始解析 Fedora RPM 数据库...")

	pkgInfo := &pkg.Pkg{
		Metadata: &pkg.Metadata{
			Lifecycle: pkg.InstalledLifecycle,
		},
		Depends: &[]pkg.Depend{},
	}

	// 创建一个包集合来存储所有找到的包
	allPackages := []*pkg.Metadata{}

	// 查询包信息
	rows, err := db.Query(`
        SELECT 
            name, version, release, arch, 
            summary, vendor, buildtime, buildhost,
            sourcerpm, license
        FROM packages
    `)
	if err != nil {
		return nil, fmt.Errorf("查询包信息失败: %v", err)
	}
	defer rows.Close()

	var totalPackages int

	// 先计算包的总数
	countRow := db.QueryRow("SELECT COUNT(*) FROM packages")
	if err := countRow.Scan(&totalPackages); err != nil {
		fmt.Println("警告: 无法获取包总数:", err)
	} else {
		fmt.Printf("发现 %d 个软件包\n", totalPackages)
	}

	var processedPackages int
	var packagesWithLicense int

	for rows.Next() {
		var name, version, release, arch string
		var summary, vendor, buildhost, sourcerpm string
		var buildtime int64
		var license string

		err := rows.Scan(&name, &version, &release, &arch,
			&summary, &vendor, &buildtime, &buildhost, &sourcerpm,
			&license)
		if err != nil {
			return nil, fmt.Errorf("读取包信息失败: %v", err)
		}

		processedPackages++

		metadata := &pkg.Metadata{
			Name:         name,
			Version:      version,
			Release:      release,
			Architecture: arch,
			Description:  summary,
			Packager:     vendor,
			BuildTime:    time.Unix(buildtime, 0).Format("2006-01-02 15:04:05"),
			BuildHost:    buildhost,
			SourcePkg:    sourcerpm,
		}

		// 添加许可证信息并记录
		if license != "" {
			metadata.License = []string{license}
			packagesWithLicense++
			fmt.Printf("软件包 %s 的许可证: %s\n", name, license)
		} else {
			fmt.Printf("警告：软件包 %s 没有许可证信息\n", name)
		}

		// 生成 CPE
		metadata.CPE = fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", name, version)

		// 生成 PURL
		namespace := "fedora" // 假设是 Fedora
		distro := "fedora-" + version
		purl := pkg.RpmPackageURL(packageurl.TypeRPM, namespace, name, arch, sourcerpm, version, release, distro)
		metadata.PURL = purl

		// 生成 BOMRef
		bomRef, err := pkg.GetBomRef(purl, struct {
			Name         string
			Version      string
			Architecture string
			timestamp    time.Time
		}{
			Name:         name,
			Version:      version,
			Architecture: arch,
			timestamp:    time.Now(),
		}, "package-id")
		if err != nil {
			return nil, fmt.Errorf("生成BOMRef失败: %v", err)
		}
		metadata.BomRef = bomRef

		// 将包添加到集合
		allPackages = append(allPackages, metadata)

		fmt.Printf("解析到软件包: %s (版本: %s-%s)\n", metadata.Name, metadata.Version, metadata.Release)
	}

	// 设置第一个包为主包
	if len(allPackages) > 0 {
		pkgInfo.Metadata = allPackages[0]
	}

	fmt.Printf("成功处理 %d 个软件包中的 %d 个\n", totalPackages, processedPackages)
	fmt.Printf("其中有 %d 个软件包包含许可证信息\n", packagesWithLicense)

	return pkgInfo, nil
}

// parseRpmDb 解析 OpenEuler 的 Packages.db 文件
func parseRpmDb(filePath string, imagePath string) (*pkg.Pkg, error) {
	// TODO: 实现 rpm 数据库解析
	// 1. 使用 rpm 相关库打开数据库
	// 2. 读取并解析包信息
	// 3. 存储解析结果
	db, err := rpmdb.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("解析rpmdb数据库信息时出错：%v", err)
	}
	defer db.Close()

	fmt.Println("开始解析 RPM 数据库...")

	packages, err := db.ListPackages()
	if err != nil {
		return nil, fmt.Errorf("解析rpmdb数据库包列表信息时出错：%v", err)
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

	totalPackages := len(packages)
	fmt.Printf("发现 %d 个软件包\n", totalPackages)

	var processedPackages int
	var packagesWithLicense int

	for _, entry := range packages {
		if entry == nil {
			continue
		}

		processedPackages++

		metadata := &pkg.Metadata{
			Name:         entry.Name,
			Version:      entry.Version,
			Release:      entry.Release,
			Architecture: entry.Arch,
			Description:  entry.Summary,
			Packager:     entry.Vendor,
			BuildTime:    time.Unix(int64(entry.InstallTime), 0).Format("2006-01-02 15:04:05"),
			BuildHost:    "", // RPM包中可能没有BuildHost字段
		}

		// 添加许可证信息
		if entry.License != "" {
			metadata.License = []string{entry.License}
			packagesWithLicense++
			fmt.Printf("软件包 %s 的许可证: %s\n", entry.Name, entry.License)
		} else {
			fmt.Printf("警告：软件包 %s 没有许可证信息\n", entry.Name)
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
			return nil, fmt.Errorf("生成BOMRef失败: %v", err)
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

		fmt.Printf("解析到软件包: %s (版本: %s-%s)\n", metadata.Name, metadata.Version, metadata.Release)
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

	fmt.Printf("成功处理 %d 个软件包中的 %d 个\n", totalPackages, processedPackages)
	fmt.Printf("其中有 %d 个软件包包含许可证信息\n", packagesWithLicense)

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

// createTempContainer 创建一个临时容器用于文件复制
func createTempContainer(imageName string) (string, error) {
	// 创建一个临时容器，不运行任何命令，仅用于文件复制
	output, err := scan_utils.RunCommand("docker", "create", imageName, "sleep", "1")
	if err != nil {
		return "", fmt.Errorf("创建容器失败: %v", err)
	}

	// 返回容器ID，清理多余的空格和换行符
	containerID := strings.TrimSpace(output)
	return containerID, nil
}

// convertToSBOMFormat 将扫描结果转换为SBOM格式
func convertToSBOMFormat(result *ScanResult) *outputSBOM {
	// 创建SBOM输出结构
	sbom := &outputSBOM{
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

	// 添加组件前记录初始大小
	initialSize := len(sbom.Components)
	fmt.Printf("开始处理软件包，初始组件数量: %d\n", initialSize)

	// 处理所有软件包 - 先使用AllPackages字段
	if result.AllPackages != nil && len(result.AllPackages) > 0 {
		fmt.Printf("处理 %d 个全局软件包...\n", len(result.AllPackages))

		// 遍历所有包并添加到SBOM，每100个包打印一次日志
		batchSize := 100
		batchCount := 0

		for i, metadata := range result.AllPackages {
			component := createPackageComponent(metadata)
			sbom.Components = append(sbom.Components, component)

			batchCount++
			if batchCount >= batchSize {
				fmt.Printf("  已处理 %d/%d 个包...\n", i+1, len(result.AllPackages))
				batchCount = 0
			}
		}

		// 添加组件后检查大小
		addedComponents := len(sbom.Components) - initialSize
		fmt.Printf("添加了 %d 个软件包组件 (期望 %d 个)\n",
			addedComponents, len(result.AllPackages))

		// 如果添加的组件数量少于预期，打印警告
		if addedComponents < len(result.AllPackages) {
			fmt.Printf("警告：有 %d 个软件包未被添加到组件列表\n",
				len(result.AllPackages)-addedComponents)
		}
	} else if result.Packages != nil && result.Packages.Metadata != nil {
		// 备用：使用packages.Metadata
		fmt.Println("使用主包信息...")

		component := createPackageComponent(result.Packages.Metadata)
		sbom.Components = append(sbom.Components, component)

		// 处理依赖
		if result.Packages.Depends != nil {
			fmt.Println("处理包依赖信息...")
			for _, dep := range *result.Packages.Depends {
				component := createDependencyComponent(&dep)
				sbom.Components = append(sbom.Components, component)
			}
		}
	}

	// 处理包之间的依赖关系
	if result.PackageMap != nil && len(result.PackageMap) > 0 {
		processDependencies(sbom, result.PackageMap)
	}

	fmt.Printf("SBOM生成完成，包含 %d 个组件和 %d 个依赖关系\n",
		len(sbom.Components), len(sbom.Dependencies))

	// 检查JSON输出大小
	jsonBytes, err := json.Marshal(sbom)
	if err == nil {
		fmt.Printf("JSON大小: %.2f MB\n", float64(len(jsonBytes))/(1024*1024))
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

				fmt.Printf("添加依赖关系: %s 依赖于 %d 个包\n", pkgInfo.Name, len(uniqueDependsList))
			}
		}
	}

	fmt.Printf("共建立 %d 个依赖关系\n", len(sbom.Dependencies))
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

	// 添加属性
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

	// 只有在存在属性时才添加properties字段
	if len(properties) > 0 {
		component.Properties = properties
	}

	return component
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

	// 使用cyclonedx属性
	properties := getMetadataComponentProperties(&dep.Metadata)
	if properties != nil && len(*properties) > 0 {
		var props []map[string]string
		for _, prop := range *properties {
			props = append(props, map[string]string{
				"name":  prop.Name,
				"value": prop.Value,
			})
		}

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

		depComponent.Properties = props
	} else {
		// 只添加依赖特定属性
		var props []map[string]string
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

		if len(props) > 0 {
			depComponent.Properties = props
		}
	}

	return depComponent
}

// getMetadataComponentProperties 从Metadata获取属性列表
func getMetadataComponentProperties(m *pkg.Metadata) *[]cyclonedx.Property {
	var out []cyclonedx.Property
	if m.Release != "" {
		out = append(out, cyclonedx.Property{
			Name:  "release",
			Value: m.Release,
		})
	}
	if m.IsNative != "" {
		out = append(out, cyclonedx.Property{
			Name:  "isNativePackage",
			Value: m.IsNative,
		})
	}
	if m.Architecture != "" {
		out = append(out, cyclonedx.Property{
			Name:  "architecture",
			Value: m.Architecture,
		})
	}
	if m.SourcePkg != "" {
		out = append(out, cyclonedx.Property{
			Name:  "sourcePkg",
			Value: m.SourcePkg,
		})
	}
	if len(m.Sources) != 0 {
		out = append(out, cyclonedx.Property{
			Name:  "sourceFiles",
			Value: strings.Join(m.Sources, ", "),
		})
	}
	if m.Maintainer != "" {
		out = append(out, cyclonedx.Property{
			Name:  "maintainer",
			Value: m.Maintainer,
		})
	}
	if m.OriginalMaintainer != "" {
		out = append(out, cyclonedx.Property{
			Name:  "originalMaintainer",
			Value: m.OriginalMaintainer,
		})
	}
	if m.Packager != "" {
		out = append(out, cyclonedx.Property{
			Name:  "packager",
			Value: m.Packager,
		})
	}
	if m.BuildTime != "" {
		out = append(out, cyclonedx.Property{
			Name:  "buildTime",
			Value: m.BuildTime,
		})
	}
	if m.BuildHost != "" {
		out = append(out, cyclonedx.Property{
			Name:  "buildHost",
			Value: m.BuildHost,
		})
	}
	if m.PackageList != "" {
		out = append(out, cyclonedx.Property{
			Name:  "packageList",
			Value: m.PackageList,
		})
	}
	if m.Section != "" {
		out = append(out, cyclonedx.Property{
			Name:  "section",
			Value: m.Section,
		})
	}
	if m.Priority != "" {
		out = append(out, cyclonedx.Property{
			Name:  "priority",
			Value: m.Priority,
		})
	}
	return &out
}
