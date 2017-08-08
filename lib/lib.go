package dlverify

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
)

// ALL THE TODOS

// Download the file
func Download(url string, verbose bool) (string, error) {
	// Grab a temporary directory & filename to work with
	dir := os.TempDir()
	fileName := path.Base(url)
	localPath := fmt.Sprintf("%s/%s", dir, fileName)

	if verbose {
		fmt.Printf("Download - creating temporary file: %s", localPath)
	}

	// Create the local temporary file (and close it when we're done)
	out, err := os.Create(localPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	if verbose {
		fmt.Printf("Download - fetching file from: %s", url)
	}

	// Fetch the file
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Copy response to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}

	return localPath, nil
}
