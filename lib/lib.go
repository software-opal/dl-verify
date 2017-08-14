package dlverify

import (
	"io"
	"net/http"
	"os"
	"path"

	log "github.com/sirupsen/logrus"
)

// ALL THE TODOS

// DownloadToTemporaryFile the file
func DownloadToTemporaryFile(folder, url string) (string, error) {
	localPath := path.Join(folder, path.Base(url))

	out, err := os.Create(localPath)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err, "path": localPath,
		}).Error("Failed to open file")
		return "", err
	}
	defer out.Close()

	log.WithFields(log.Fields{
		"url": url, "target": localPath,
	}).Debug("Starting download")

	resp, err := http.Get(url)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err, "url": url,
		}).Error("Failed to get URL")
		return "", err
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err, "target": localPath,
		}).Error("Failed to copy to file")
		return "", err
	}

	return localPath, nil
}
