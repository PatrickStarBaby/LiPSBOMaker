package installed

import (
	"fmt"
	"os"
	"slp/utils"
)

// installAptRdepends 安装 apt-rdepends
func installAptRdepends() error {
	fmt.Println("apt-rdepends 未安装，正在安装...")
	if _, err := scan_utils.RunCommand("sudo", "apt-get", "update"); err != nil {
		return fmt.Errorf("failed to update package lists: %v", err)
	}

	if _, err := scan_utils.RunCommand("sudo", "apt-get", "install", "-y", "apt-rdepends"); err != nil {
		return fmt.Errorf("failed to install apt-rdepends: %v", err)
	}
	return nil
}

func GetInstalledDebInfo(pkgName string) {
	//判断本地是否安装apt-rdepends
	if !scan_utils.CheckCommandExists("apt-rdepends") {
		if err := installAptRdepends(); err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		}
	} else {
		fmt.Println("apt-rdepends 已安装")
	}

	scan_utils.RunCommand("apt-rdepends", "pkgName")
}
