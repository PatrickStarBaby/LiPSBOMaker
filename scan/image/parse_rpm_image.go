package image

import scan_utils "slp/utils"

func ParseRpmDB(path string) error {
	scan_utils.RunCommand("dnf", "install", "syft")
	/*if path == "" {
		path = "/var/lib/rpm"
	}
	db, err := rpmdb.Open(path)
	if err != nil {
		return fmt.Errorf("解析rpmdb数据库信息时出错：%v", err)
	}
	packages, err := db.ListPackages()
	if err != nil {
		return fmt.Errorf("解析rpmdb数据库包列表信息时出错：%v", err)
	}
	for _, entry := range packages {
		if entry == nil {
			continue
		}
		fmt.Println(entry.Name, entry.Version, entry.Requires, entry.Vendor)
	}*/
	return nil
}
