// Package source 获取编译环境信息，例如构建依赖的具体版本等
package source

import (
	"encoding/json"
	"fmt"
	"github.com/sassoftware/go-rpmutils"
	"os"
	"pault.ag/go/debian/control"
	_package "slp/package"
	"slp/scan/installed"
	scan_utils "slp/utils"
	"strings"
)

// deb包中存在'或'依赖组的关系，同一种类型的依赖可能有一组包都满足
type BuildDepPkgGroup []_package.Pkg

type DebBuildEnv struct {
	BuildDepends      []BuildDepPkgGroup `json:"build-depends,omitempty"`
	BuildDependsIndep []BuildDepPkgGroup `json:"build-depends-indep,omitempty"`
	BuildDependsArch  []BuildDepPkgGroup `json:"build-depends-arch,omitempty"`
}

// rpm包的一个依赖功能可能有多个提供者
type buildDepProviderGroup struct {
	RequireProvide string         `json:"require-provide,omitempty"` // 依赖的功能名
	Provider       []_package.Pkg `json:"provider,omitempty"`        // 该功能名的提供者，本地可能存在多个
}
type RpmBuildEnv struct {
	BuildRequires []buildDepProviderGroup `json:"build-requires,omitempty"`
}

func RecordRpmBuildEnvInformation(rpmSourcePkgPath string) error {
	err, rpmBuildEnv := FetchRpmBuildDep(rpmSourcePkgPath)
	if err != nil {
		return err
	}

	fmt.Println("-----------------Write to file--------------------")
	// 将结构体转换为JSON格式（格式化缩进）
	jsonData, err := json.MarshalIndent(rpmBuildEnv, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON serialization failed: %v", err)
	}

	// 创建 JSON 文件
	file, err := os.Create("buildEnv.json")
	if err != nil {
		return fmt.Errorf("Failed to create file: %v", err)
	}
	defer file.Close()

	// 将 JSON 数据写入文件
	_, err = file.Write(jsonData)
	if err != nil {
		return fmt.Errorf("Failed to write to file: %v", err)
	}

	fmt.Println("Build environment information written successfully!！")
	return nil
}

func FetchRpmBuildDep(rpmSourcePkgPath string) (error, *RpmBuildEnv) {
	// 读取rpm源码包
	file, err := os.Open(rpmSourcePkgPath)
	if err != nil {
		return fmt.Errorf("failed to open RPM file: %v", err), nil
	}
	defer file.Close()
	rpm, err := rpmutils.ReadRpm(file)
	if err != nil {
		return fmt.Errorf("failed to read RPM file: %v", err), nil
	}

	buildRequireNameList, err := rpm.Header.GetStrings(rpmutils.REQUIRENAME)
	var buildRequires []buildDepProviderGroup
	for _, v := range buildRequireNameList {
		err, provider := getRPMProvider(v)
		// 发生错误时，例如出现rpmlib(CompressedFileNames)等，还是插入到列表中
		if err != nil {
			//fmt.Println(err)
			//continue
		}
		buildRequires = append(buildRequires, buildDepProviderGroup{
			RequireProvide: v,
			Provider:       provider,
		})
	}

	return nil, &RpmBuildEnv{
		BuildRequires: buildRequires,
	}
}

// 通过rpm -q --whatprovides xxx 命令获取Provider列表
func getRPMProvider(provide string) (error, []_package.Pkg) {
	res, err := scan_utils.RunCommand("rpm", "-q", "--whatprovides", provide)
	if err != nil {
		//fmt.Println(res)
		return fmt.Errorf("rpm -q --whatprovides Command execution failed:%v", err), nil
	}
	lines := strings.Split(res, "\n")
	var providerList []_package.Pkg
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			pkg, err := scan_utils.SplitRPMNameWithoutEpoch(trimmedLine)
			if err != nil {
				fmt.Println(err)
				continue
			}
			err, provider := installed.ParseInstalledRpm(pkg.Name)
			if err != nil {
				fmt.Println(err)
				continue
			}
			providerList = append(providerList, *provider)
		}
	}
	return nil, providerList
}

func RecordDebBuildEnvInformation(dscFilePath string) error {
	err, debBuildEnv := FetchDebBuildDep(dscFilePath)
	if err != nil {
		return err
	}
	fmt.Println("-----------------写入文件--------------------")
	// 将结构体转换为JSON格式（格式化缩进）
	jsonData, err := json.MarshalIndent(debBuildEnv, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON serialization failed: %v", err)
	}

	// 创建 JSON 文件
	file, err := os.Create("buildEnv.json")
	if err != nil {
		return fmt.Errorf("Failed to create file: %v", err)
	}
	defer file.Close()

	// 将 JSON 数据写入文件
	_, err = file.Write(jsonData)
	if err != nil {
		return fmt.Errorf("Failed to write to file: %v", err)
	}

	fmt.Println("Build environment information written successfully!！")
	return nil
}

func FetchDebBuildDep(dscFilePath string) (error, *DebBuildEnv) {
	// 打开dsc文件
	file, err := os.Open(dscFilePath) // dsc文件路径
	if err != nil {
		return fmt.Errorf("Unable to open the .dsc file: %v", err), nil
	}
	defer file.Close()

	// 三方包解析dsc文件
	var dscFields control.DSC
	if err := control.Unmarshal(&dscFields, file); err != nil {
		return fmt.Errorf("Unable to parse the .dsc file: %v", err), nil
	}

	buildDeps := []BuildDepPkgGroup{}
	buildDepsIndep := []BuildDepPkgGroup{}
	buildDepsArch := []BuildDepPkgGroup{}

	for _, d := range dscFields.BuildDepends.Relations {
		var deps BuildDepPkgGroup
		for _, p := range d.Possibilities {
			err, dep := installed.ParseInstalledDeb(p.Name)
			if err == nil {
				deps = append(deps, *dep)
			}
		}
		buildDeps = append(buildDeps, deps)
	}
	for _, d := range dscFields.BuildDependsIndep.Relations {
		var deps BuildDepPkgGroup
		for _, p := range d.Possibilities {
			err, dep := installed.ParseInstalledDeb(p.Name)
			if err == nil {
				deps = append(deps, *dep)
			}
		}
		buildDepsIndep = append(buildDepsIndep, deps)
	}
	for _, d := range dscFields.BuildDependsArch.Relations {
		var deps BuildDepPkgGroup
		for _, p := range d.Possibilities {
			err, dep := installed.ParseInstalledDeb(p.Name)
			if err == nil {
				deps = append(deps, *dep)
			}
		}
		buildDepsArch = append(buildDepsArch, deps)
	}

	return nil, &DebBuildEnv{
		BuildDepends:      buildDeps,
		BuildDependsIndep: buildDepsIndep,
		BuildDependsArch:  buildDepsArch,
	}
}
