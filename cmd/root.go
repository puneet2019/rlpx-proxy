package cmd

import (
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "peer-sniffer",
	Short: "XDC Peer Sniffer - Monitor XDC network traffic",
	Long:  `A tool to capture and analyze XDC network traffic.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func getPeerdDir() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, ".peerd"), nil
}

func ensurePeerdDir() error {
	peerdDir, err := getPeerdDir()
	if err != nil {
		return err
	}
	return os.MkdirAll(peerdDir, 0755)
}