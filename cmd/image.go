package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(imageCmd)
}

var imageCmd = &cobra.Command{
	Use:   "image [SOURCE]",
	Short: "Generate an SBOM for Linux image",
	Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from Linux image(docker image or iso image)",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			fmt.Println("Parameters are missing, Usage: ")
			fmt.Println("slp image [SOURCE]")
		} else {
			fmt.Println("Generate SBOM for Linux image for", args[0])
		}

	},
}
