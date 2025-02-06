package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"path/filepath"
	"slp/scan/source"
)

func init() {
	rootCmd.AddCommand(recordBuildEnvInfoCmd)
}

var recordBuildEnvInfoCmd = &cobra.Command{
	Use:   "record",
	Short: "record the build environment information for Linux source packages",
	Long:  `record the build environment information for Linux source packages`,
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Println("这是在记录源码包的本地构建信息")
		if len(args) == 0 {
			fmt.Println("Parameters are missing, Usage: ")
			fmt.Println("slp record [SOURCE]")
		} else {
			recordEnv(args[0])
		}

	},
}

// deb源码：传入.dsc文件的路径
// rpm源码：直接传入rpm源码包的路径
func recordEnv(filePath string) {
	ext := filepath.Ext(filePath)
	// 根据文件后缀判断 deb/RPM 体系
	if ext == ".rpm" {
		// rpm体系 传入 rpm源码包的路径
		err := source.RecordRpmBuildEnvInformation(filePath)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		// deb体系 传入 .dsc 文件路径
		err := source.RecordDebBuildEnvInformation(filePath)
		if err != nil {
			fmt.Println(err)
		}

	}
}
