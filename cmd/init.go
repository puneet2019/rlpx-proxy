package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the .peerd directory with default config and .env",
	Long:  `Creates the .peerd directory in the home folder with default configuration and environment files.`,
	Run: func(cmd *cobra.Command, args []string) {
		force, _ := cmd.Flags().GetBool("force")
		initializePeerdDir(force)
	},
}

func init() {
	initCmd.Flags().Bool("force", false, "Force initialization even if .peerd directory exists")
	rootCmd.AddCommand(initCmd)
}

func initializePeerdDir(force bool) {
	peerdDir, err := getPeerdDir()
	if err != nil {
		fmt.Printf("Error getting .peerd directory: %v\n", err)
		return
	}

	// Check if directory exists
	exists := true
	if _, err := os.Stat(peerdDir); os.IsNotExist(err) {
		exists = false
	}

	if exists && !force {
		fmt.Printf(".peerd directory already exists at: %s\n", peerdDir)
		fmt.Println("Use --force flag to overwrite existing files")
		return
	}

	if !exists {
		// Create the directory
		if err := os.MkdirAll(peerdDir, 0755); err != nil {
			fmt.Printf("Error creating .peerd directory: %v\n", err)
			return
		}
		fmt.Printf("Created .peerd directory at: %s\n", peerdDir)
	} else {
		fmt.Printf(".peerd directory already exists at: %s\n", peerdDir)
	}

	// Create default config file
	configPath := filepath.Join(peerdDir, "config.json")
	configExists := true
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configExists = false
	}

	if !configExists {
		defaultConfig := `{
  "interface": "en0",
  "log_xdc_only": false,
  "xdc_nodes": [],
  "xdc_ports": [
    "30303",
    "30304",
    "30305",
    "30306",
    "30307",
    "30308",
    "30309",
    "30310",
    "30311",
    "30312",
    "30313"
  ],
  "buffer_size": 1600,
  "promiscuous_mode": true
}`
		if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
			fmt.Printf("Error creating config file: %v\n", err)
		} else {
			fmt.Printf("Created default config file at: %s\n", configPath)
		}
	} else {
		fmt.Printf("Config file already exists at: %s\n", configPath)
	}

	// Create default .env file
	envPath := filepath.Join(peerdDir, ".env")
	envExists := true
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		envExists = false
	}

	if !envExists {
		defaultEnv := `# XDC Private Key for decrypting encrypted traffic
# XDC_PRIVATE_KEY=your_private_key_here

# Logging configuration
LOG_LEVEL=info

# Sliding window duration in seconds
WINDOW_DURATION=100
`
		if err := os.WriteFile(envPath, []byte(defaultEnv), 0644); err != nil {
			fmt.Printf("Error creating .env file: %v\n", err)
		} else {
			fmt.Printf("Created default .env file at: %s\n", envPath)
		}
	} else {
		fmt.Printf(".env file already exists at: %s\n", envPath)
	}

	// Create peer data file if it doesn't exist
	peerDataPath := filepath.Join(peerdDir, "peer-data.json")
	peerDataExists := true
	if _, err := os.Stat(peerDataPath); os.IsNotExist(err) {
		peerDataExists = false
	}

	if !peerDataExists {
		// Create an empty JSON object
		if err := os.WriteFile(peerDataPath, []byte("{}"), 0644); err != nil {
			fmt.Printf("Error creating peer-data.json file: %v\n", err)
		} else {
			fmt.Printf("Created peer data file at: %s\n", peerDataPath)
		}
	} else {
		fmt.Printf("Peer data file already exists at: %s\n", peerDataPath)
	}

	fmt.Println("\nInitialization complete!")
}