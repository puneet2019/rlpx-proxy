package main

import (
	"fmt"
	"os"

	"peer-sniffer/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
