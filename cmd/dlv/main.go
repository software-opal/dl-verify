package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"

	"github.com/leesdolphin/dl-verify/gpg"
	"github.com/leesdolphin/dl-verify/lib"
)

// Config object defines command line arguments
type Config struct {
	URL     string `short:"u" long:"url" description:"URL to fetch" required:"true"`
	Verbose bool   `short:"v" long:"verbose" description:"Verbose output mode"`
	OutDir  string `short:"o" long:"output-dir" description:"File output directory"`

	Checksums dlverify.ChecksumConfig `group:"Checksums Verification"`
	// GPG       gpg.SignatureConfig     `group:"GPG Signature Verification"`
}

// ConfigureLogging sets the logger's settings to those specified in Config
func (config Config) ConfigureLogging() error {
	log.SetOutput(os.Stderr)

	if config.Verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}
	return nil
}

func writeOutFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err, "path": path,
		}).Error("Failed to Open path")
		return err
	}
	_, err = io.Copy(os.Stdout, file)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err, "path": path,
		}).Error("Failed to Open path")
		return err
	}
	return nil
}

func main() {
	{
		key, _ := gpg.NewKeyID("595E85A6B1B4779EA4DAAEC70B588DFF0527A9B7")
		ksi := gpg.DefaultKeyServerInformation()
		k, err := ksi.DownloadKey(context.Background(), key, nil)
		fmt.Printf("%#+v\n\n%#+v", k, err)
	}

	// Parse command line arguments
	args := Config{}
	_, err := flags.Parse(&args)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Parse failed")
		os.Exit(3)
	}
	err = args.ConfigureLogging()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to configure logging:\n%s\n", err)
		os.Exit(3)
	}
	err = args.Checksums.ValidateGivenChecksums()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Given checksums were invalid:\n%s\n", err)
		os.Exit(3)
	}

	tempFolder, err := ioutil.TempDir("", "dlverify")
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Error("Failed to create temporary directory.")
		fmt.Fprintf(
			os.Stderr,
			"Failed to create a temporary directory.\n%s\n",
			err,
		)
		os.Exit(4)
	}
	defer os.RemoveAll(tempFolder)
	path, err := dlverify.DownloadToTemporaryFile(tempFolder, args.URL)

	// This will be set to true if *any* form of verification has been done.
	isVerified := false

	verification, err := args.Checksums.VerifyFileChecksums(path)
	if err != nil {
		os.Exit(4)
	}
	log.WithFields(log.Fields{
		"valid":   verification.Valid,
		"invalid": verification.Invalid,
	}).Info("Checksum Verification Results.")
	if verification.IsInvalid() {
		fmt.Fprintf(
			os.Stderr,
			"Checksum verification failed.\n%s.\n",
			verification.ToMessage(),
		)
		os.Exit(1)
	}
	isVerified = isVerified || (!verification.IsNoOp())

	if !isVerified {
		// No verification!
		fmt.Fprintln(
			os.Stderr,
			"No verification was done. Cannot assert the validity of the file",
		)
		os.Exit(1)
	}
	// Completed verification steps. Now to dump to StdOut

	err = writeOutFile(path)
	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"Failed to write out file.\n"+
				"CAUTION: Some file data may have been sent already.",
		)
		os.Exit(4)
	}
}
