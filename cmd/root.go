package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

/*
	命令：
	slp version
	slp image [SOURCE] --output=[Filename]
	slp package --lifecycle=["source"/"release"/"installed"] [SOURCE] --output=[Filename]
*/

var rootCmd = &cobra.Command{
	Use:   "slp",
	Short: "slp is a very fast SBOM generator for Linux Package",
	Long:  `slp is a very fast SBOM generator for Linux Package`,
	/*PersistentPreRun: func(cmd *cobra.Command, args []string) {
		fmt.Println("在执行任何命令之前调用 PersistentPreRun")
	},
	PreRun: func(cmd *cobra.Command, args []string) {
		fmt.Println("在执行该命令之前调用 PreRun")
	},*/
	Run: func(cmd *cobra.Command, args []string) {

	},
	/*PostRun: func(cmd *cobra.Command, args []string) {
		fmt.Println("在执行完该命令之后调用 PostRun")
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		fmt.Println("在执行完任何命令之后调用 PersistentPostRun")
	},*/
}

func init() {
	//生命周期参数："source"/"release"/"installed"
	//rootCmd.PersistentFlags().StringP("lifecycle", "l", "", "Specifies the lifecycle of the package")
	//rootCmd.MarkPersistentFlagRequired("lifecycle") //生命周期必传

	//颗粒度参数："image"/"software"
	//rootCmd.PersistentFlags().StringP("granularity", "g", "software", "Specifies the granularity of the package")
	//rootCmd.MarkPersistentFlagRequired("granularity") //颗粒度必传

}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
