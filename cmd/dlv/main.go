package main

import (
	"fmt"

	"github.com/jessevdk/go-flags"
	// Lib include here, but it's in my package path and cbf fixing it right now.
	//github.com/leesdolphin/dl-verify/lib
)

// Config object defines command line arguments
type Config struct {
	URL     string `short:"u" long:"url" description:"URL to fetch" required:"true"`
	Verbose bool   `short:"v" long:"verbose" description:"Verbose output mode"`
	SHA512  string `short:"s" long:"sha512" description:"SHA512 checksum for downloaded file"`
	OutDir  string `short:"o" long:"output-dir" description:"File output directory"`
}

func main() {
	// Parse command line arguments
	a := Config{}
	flags.Parse(&a)

	if a.Verbose {
		fmt.Printf("Download-Verify")
	}

}
