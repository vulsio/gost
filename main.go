package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vulsio/gost/cmd"
	"github.com/vulsio/gost/config"
)

func main() {
	var v = flag.Bool("v", false, "Show version")
	flag.Parse()
	if *v {
		fmt.Printf("gost-%s-%s\n", config.Version, config.Revision)
		os.Exit(0)
	}

	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
