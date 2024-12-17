package installed

import (
	"fmt"
	_package "slp/package"
	scan_utils "slp/utils"
)

func ParseInstalledRpm(pkgName string) (error, *_package.Pkg) {
	GetInstalledRpmInfo(pkgName)
	return nil, nil
}

func GetInstalledRpmInfo(pkgName string) {
	requirePkgs, err := scan_utils.RunCommand("dnf", "repoquery", "--requires", "--resolve", "--installed", pkgName)
	if err != nil {
		fmt.Println("dnf repoquery --requires --resolve命令执行失败：", err)
		return
	}
	fmt.Println(requirePkgs)
	// 使用 rpmutils 提取包名信息
	/*nevra, err := scan_utils.SplitRPMName(rpmName)
	if err != nil {
		log.Fatalf("解析失败: %v", err)
	}

	// 输出结果
	fmt.Println("解析结果:")
	fmt.Printf("Name: %s\n", nevra.Name)
	fmt.Printf("Epoch: %d\n", nevra.Epoch)
	fmt.Printf("Version: %s\n", nevra.Version)
	fmt.Printf("Release: %s\n", nevra.Release)
	fmt.Printf("Arch: %s\n", nevra.Arch)*/
}
