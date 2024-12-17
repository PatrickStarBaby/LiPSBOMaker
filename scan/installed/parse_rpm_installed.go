package installed

import scan_utils "slp/utils"

func GetInstalledRpmInfo(pkgName string) {
	scan_utils.RunCommand("dnf deplist", "pkgName")
}
