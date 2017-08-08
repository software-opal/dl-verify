package dlverify

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLib(t *testing.T) {
	nyanUrl := "https://media.giphy.com/media/sIIhZliB2McAo/giphy.gif"

	t.Run("Downloads files to temporary directories", func(t *testing.T) {
		filePath, err := Download(nyanUrl, false)
		assert.Nil(t, err)

		// Check new temp file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			t.Errorf("File %s does not exist", filePath)
			t.FailNow()
		}

	})

}
