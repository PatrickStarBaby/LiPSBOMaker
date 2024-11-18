package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of slp",
	Long:  `Print the version number of slp`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("slp v0.9")
	},
}
