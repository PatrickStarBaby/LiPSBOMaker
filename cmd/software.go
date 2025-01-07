package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"path/filepath"
	"slp/file"
	"slp/format/cyclonedxjson"
	"slp/scan/installed"
	"slp/scan/release"
	"slp/scan/source"
	scan_utils "slp/utils"
	"strings"
)

var (
	allowedLifecycleArgs = []string{"source", "release", "installed"}
)

func init() {
	//生命周期参数："source"/"release"/"installed"
	softwareCmd.PersistentFlags().StringP("lifecycle", "l", "", "Specifies the lifecycle of the package")
	err := softwareCmd.MarkPersistentFlagRequired("lifecycle") //生命周期必传
	if err != nil {
		fmt.Errorf("failed to markPersistentFlagRequired: %v", err)
	}

	//输出文件参数
	softwareCmd.PersistentFlags().StringP("output", "o", "result.json", "Specifies the output file of the SBOM (default: result.json)")

	rootCmd.AddCommand(softwareCmd)
}

var softwareCmd = &cobra.Command{
	Use:   "package",
	Short: "Generate SBOM for Linux software packages",
	Long:  `Generate SBOM for Linux software packages`,
	Run: func(cmd *cobra.Command, args []string) {
		lifecycle, _ := cmd.Flags().GetString("lifecycle")
		output, _ := cmd.Flags().GetString("output")
		// 按生命周期参数分别处理
		switch lifecycle {
		case "source":
			fmt.Println("这是要生成源码阶段SBOM")
			if len(args) == 0 {
				fmt.Println("Parameters are missing, Usage: ")
				fmt.Println("slp package -l=[\"source\"/\"release\"/\"installed\"] [SOURCE] --output [FILENAME]")
			} else {
				sourceScan(args[0], output)
			}
		case "release":
			fmt.Println("这是要生成二进制交付阶段SBOM")
			if len(args) == 0 {
				fmt.Println("Parameters are missing, Usage: ")
				fmt.Println("slp package -l=[\"source\"/\"release\"/\"installed\"] [SOURCE] --output [FILENAME]")
			} else {
				releaseScan(args[0], output)
			}
		case "installed":
			fmt.Println("这是要生成二进制使用阶段SBOM")
			if len(args) == 0 {
				fmt.Println("Parameters are missing, Usage: ")
				fmt.Println("slp package -l=[\"source\"/\"release\"/\"installed\"] [SOURCE] --output [FILENAME]")
			} else {
				installedScan(args[0], output)
			}
		default:
			fmt.Println(fmt.Sprintf("invalid argument: %s (allowed values are: %s)", lifecycle, strings.Join(allowedLifecycleArgs, ", ")))
		}
	},
}

// deb源码：由于deb源码是多个文件组成的，首先解压得到主文件夹，然后把.dsc文件复制到主文件夹，接着传入复制后的.dsc文件的路径
// rpm源码：直接传入rpm源码包的路径
func sourceScan(filePath string, output string) {
	ext := filepath.Ext(filePath)
	// 根据文件后缀判断 deb/RPM 体系
	if ext == ".rpm" {
		err, pkg := source.ParseSourceRpmFile(filePath)
		if err != nil {
			fmt.Println(err)
		}
		err = file.WriteCycloneDX(cyclonedxjson.ToFormatModel(pkg), output)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		//此处参数一filePath就是.dsc文件移入主目录后的路径，例：/apt-2.7.14build2/apt_2.7.14build2.dsc
		//参数二会截取得到主目录/apt-2.7.14build2，并拼接上/debian/patches
		err, pkg := source.ParseSourceDebFile(filePath, filepath.Join(filepath.Dir(filePath), "debian/patches"), filepath.Join(filepath.Dir(filePath), "debian/copyright"))
		if err != nil {
			fmt.Println(err)
		}
		err = file.WriteCycloneDX(cyclonedxjson.ToFormatModel(pkg), output)
		if err != nil {
			fmt.Println(err)
		}
	}
}

// deb二进制：直接传入deb二进制包的路径
// rpm二进制：直接传入rpm二进制包的路径
func releaseScan(filePath string, output string) {
	ext := filepath.Ext(filePath)
	if ext == ".deb" {
		err, pkg := release.ParseReleaseDebFile(filePath)
		if err != nil {
			fmt.Println(err)
		}
		err = file.WriteCycloneDX(cyclonedxjson.ToFormatModel(pkg), output)
		if err != nil {
			fmt.Println(err)
		}
	}
	if ext == ".rpm" {
		err, pkg := release.ParseReleaseRpmFile(filePath)
		if err != nil {
			fmt.Println(err)
		}
		err = file.WriteCycloneDX(cyclonedxjson.ToFormatModel(pkg), output)
		if err != nil {
			fmt.Println(err)
		}
	}
}

// rpm,deb都是直接输入软件包名即可，例如：slp package -l=installed bash --output test.json
func installedScan(pkgName string, output string) {
	//在基于 RPM 的系统（如 RHEL、CentOS、Fedora）上，rpm 命令必然存在
	//通过判断rpm命令是否存在的方式，来确定当前的系统环境到底是rpm还是deb
	if scan_utils.CheckCommandExists("rpm") {
		//rpm体系
		err, pkg := installed.ParseInstalledRpm(pkgName)
		if err != nil {
			fmt.Println(err)
		}
		err = file.WriteCycloneDX(cyclonedxjson.ToFormatModel(pkg), output)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		//deb体系
		err, pkg := installed.ParseInstalledDeb(pkgName)
		if err != nil {
			fmt.Println(err)
		}
		err = file.WriteCycloneDX(cyclonedxjson.ToFormatModel(pkg), output)
		if err != nil {
			fmt.Println(err)
		}
	}
}
