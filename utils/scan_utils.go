package scan_utils

import (
	"github.com/sassoftware/go-rpmutils"
	"os"
)

// 转换版本符号（>=，<=等）
func GetOperator(flag uint32) string {
	switch {
	case flag&rpmutils.RPMSENSE_LESS != 0 && flag&rpmutils.RPMSENSE_EQUAL != 0:
		return "<="
	case flag&rpmutils.RPMSENSE_GREATER != 0 && flag&rpmutils.RPMSENSE_EQUAL != 0:
		return ">="
	case flag&rpmutils.RPMSENSE_LESS != 0:
		return "<"
	case flag&rpmutils.RPMSENSE_GREATER != 0:
		return ">"
	case flag&rpmutils.RPMSENSE_EQUAL != 0:
		return "="
	default:
		return ""
	}
}

// 判断路径是否存在
func PathExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
