// Package source 获取编译环境信息，例如构建依赖的具体版本等
package source

import (
	"encoding/json"
	"fmt"
	"os"
	"pault.ag/go/debian/control"
	_package "slp/package"
	"slp/scan/installed"
)

// deb包中存在'或'依赖组的关系，同一种类型的依赖可能有一组包都满足
type buildDepPkgGroup []_package.Pkg

type DebBuildEnv struct {
	BuildDepends      []buildDepPkgGroup `json:"build-depends,omitempty"`
	BuildDependsIndep []buildDepPkgGroup `json:"build-depends-indep,omitempty"`
	BuildDependsArch  []buildDepPkgGroup `json:"build-depends-arch,omitempty"`
}

type RpmBuildEnv struct {
}

func RecordDebBuildEnvInformation(dscFilePath string) error {
	err, debBuildEnv := FetchDebBuildDep(dscFilePath)
	if err != nil {
		return err
	}

	// 将结构体转换为JSON格式（格式化缩进）
	jsonData, err := json.MarshalIndent(debBuildEnv, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON 序列化失败: %v", err)
	}

	// 创建 JSON 文件
	file, err := os.Create("buildEnv.json")
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	// 将 JSON 数据写入文件
	_, err = file.Write(jsonData)
	if err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	fmt.Println("构建环境信息写入成功！")
	return nil
}

func FetchRpmBuildDep() {

}

func FetchDebBuildDep(dscFilePath string) (error, *DebBuildEnv) {
	// 打开dsc文件
	file, err := os.Open(dscFilePath) // dsc文件路径
	if err != nil {
		return fmt.Errorf("无法打开dsc文件: %v", err), nil
	}
	defer file.Close()

	// 三方包解析dsc文件
	var dscFields control.DSC
	if err := control.Unmarshal(&dscFields, file); err != nil {
		return fmt.Errorf("无法解析dsc文件: %v", err), nil
	}

	buildDeps := []buildDepPkgGroup{}
	buildDepsIndep := []buildDepPkgGroup{}
	buildDepsArch := []buildDepPkgGroup{}

	for _, d := range dscFields.BuildDepends.Relations {
		var deps buildDepPkgGroup
		for _, p := range d.Possibilities {
			err, dep := installed.ParseInstalledDeb(p.Name)
			if err == nil {
				deps = append(deps, *dep)
			}
		}
		buildDeps = append(buildDeps, deps)
	}
	for _, d := range dscFields.BuildDependsIndep.Relations {
		var deps buildDepPkgGroup
		for _, p := range d.Possibilities {
			err, dep := installed.ParseInstalledDeb(p.Name)
			if err == nil {
				deps = append(deps, *dep)
			}
		}
		buildDepsIndep = append(buildDepsIndep, deps)
	}
	for _, d := range dscFields.BuildDependsArch.Relations {
		var deps buildDepPkgGroup
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
