package file

import (
	"encoding/json"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"os"
)

func WriteCycloneDX(bom *cyclonedx.BOM, fileName string) error {
	// 创建文件
	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to Create file: %v", err)
	}
	defer file.Close()

	// 将BOM数据写入文件
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ") // 美化JSON输出
	if err := encoder.Encode(bom); err != nil {
		return fmt.Errorf("failed to Write file: %v", err)
	}
	fmt.Println("SBOM 数据已写入到 " + fileName + " 文件")

	return nil
}
