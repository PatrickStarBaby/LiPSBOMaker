package image

import (
	"fmt"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

func ParseRpmDB(path string) error {
	if path == "" {
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
		fmt.Println(entry)
	}
	return nil
}
