package dlverify

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// VerificationResult holds the list of valid and invalid checksums that were checked
type VerificationResult struct {
	Valid   []string
	Invalid []string
}

func englishJoin(strs []string, sep, lastSep string) string {
	slen := len(strs)
	if slen == 0 {
		return ""
	} else if slen == 1 {
		return strs[0]
	} else {
		return fmt.Sprintf(
			"%s%s%s",
			strings.Join(strs[0:slen-1], sep),
			lastSep,
			strs[slen-1])
	}
}

// IsValid returns true when the result indicates a successful validation
func (v VerificationResult) IsValid() bool {
	return len(v.Valid) >= 1 && len(v.Invalid) == 0
}

// IsInvalid returns true when the result indicates an unsuccessful validation
func (v VerificationResult) IsInvalid() bool {
	return len(v.Invalid) >= 1
}

// IsNoOp returns true when the result indicates that no validation was
// performed.
func (v VerificationResult) IsNoOp() bool {
	return len(v.Invalid) == 0 && len(v.Valid) == 0
}

// ToMessage converts the result into a user-displayable string.
func (v VerificationResult) ToMessage() string {
	if v.IsNoOp() {
		return "The file's contents was not validated using checksums"
	} else if v.IsValid() {
		return fmt.Sprintf(
			"The file's contents succeeded validatation using %s",
			englishJoin(v.Valid, ", ", " and "),
		)
	}
	// IsInvalid() == true
	failed := fmt.Sprintf(
		"The file's contents failed validation using %s",
		englishJoin(v.Invalid, ", ", " and "),
	)
	if v.IsValid() {
		return fmt.Sprintf(
			"%s, it did succeed validation using %s",
			failed,
			englishJoin(v.Valid, ", ", " and "),
		)
	}
	return failed
}

// InvalidHashCharacters represents the error when a parameter is not a valid
// hexadecimal string.
type InvalidHashCharacters struct {
	HashType  string
	GivenHash string
}

func (e InvalidHashCharacters) Error() string {
	return fmt.Sprintf(
		"Given %s hash is not a valid hexadecimal value: `%s'",
		e.HashType,
		e.GivenHash,
	)
}

// InvalidHashLength represents the error when a parameter is not a valid
// length.
type InvalidHashLength struct {
	HashType      string
	HashHexLength int
	GivenHash     string
}

func (e InvalidHashLength) Error() string {
	return fmt.Sprintf(
		"Given %s hash expects a hexadecimal string of length %d. Got length %d: `%s'",
		e.HashType,
		e.HashHexLength,
		len(e.GivenHash), // Don't care about Unicode runes(should only be a-f0-9)
		e.GivenHash,
	)
}

// ChecksumConfig defines arguments for checking the downloaded file's checksums.
type ChecksumConfig struct {
	Sha512 string `long:"sha512" description:"SHA512 checksum for downloaded file"`
	Sha384 string `long:"sha384" description:"SHA384 checksum for downloaded file"`
	Sha256 string `long:"sha256" description:"SHA256 checksum for downloaded file"`
	Sha224 string `long:"sha224" description:"SHA224 checksum for downloaded file"`
	Sha1   string `long:"sha1"   description:"SHA1 checksum for downloaded file"`
	Md5    string `long:"md5"    description:"MD5 checksum for downloaded file"`
}

type sumPair struct {
	Name     string
	Expected string
	Hash     hash.Hash
}

// HashInfo Contains information about a single Hash type.
type HashInfo struct {
	Size int
	New  func() hash.Hash
}

// ValidHashTypes returns supported hashes, their length and their
// constructors
func ValidHashTypes() map[string]HashInfo {
	return map[string]HashInfo{
		"SHA512": {
			Size: sha512.Size,
			New:  sha512.New,
		},
		"SHA384": {
			Size: sha512.Size384,
			New:  sha512.New384,
		},
		"SHA256": {
			Size: sha256.Size,
			New:  sha256.New,
		},
		"SHA224": {
			Size: sha256.Size224,
			New:  sha256.New224,
		},
		"SHA1": {
			Size: sha1.Size,
			New:  sha1.New,
		},
		"MD5": {
			Size: md5.Size,
			New:  md5.New,
		},
	}
}

// AsMap converts the stored Checksums into a Map with the same keys
// as ValidHashTypes
func (config ChecksumConfig) AsMap() map[string]string {
	return map[string]string{
		"SHA512": strings.ToLower(config.Sha512),
		"SHA384": strings.ToLower(config.Sha384),
		"SHA256": strings.ToLower(config.Sha256),
		"SHA224": strings.ToLower(config.Sha224),
		"SHA1":   strings.ToLower(config.Sha1),
		"MD5":    strings.ToLower(config.Md5),
	}
}

// ValidateGivenChecksums validates that any given Checksums are the correct
// length and are lowercase hexadecimal
func (config ChecksumConfig) ValidateGivenChecksums() error {
	allChecksums := config.AsMap()
	validTypes := ValidHashTypes()
	for hashKey := range allChecksums {
		hash := allChecksums[hashKey]
		hashType := validTypes[hashKey]
		if hash == "" {
			continue
		}
		if hex.EncodedLen(hashType.Size) != len(hash) {
			return InvalidHashLength{
				HashType:      hashKey,
				HashHexLength: hex.EncodedLen(hashType.Size),
				GivenHash:     hash,
			}
		}
		_, err := hex.DecodeString(hash)
		if err != nil {
			return InvalidHashCharacters{
				HashType:  hashKey,
				GivenHash: hash,
			}
		}
	}
	return nil
}

// VerifyFileChecksums checks that the hashes for the given path is valid.
func (config ChecksumConfig) VerifyFileChecksums(path string) (*VerificationResult, error) {
	allChecksums := config.AsMap()
	validTypes := ValidHashTypes()
	result := new(VerificationResult)
	for hashKey := range allChecksums {
		expectedHash := allChecksums[hashKey]
		hashImpl := validTypes[hashKey].New()
		if expectedHash == "" {
			continue
		}

		file, err := os.Open(path)
		if err != nil {
			log.WithFields(log.Fields{
				"err": err, "path": path,
			}).Error("Failed to Open path")
			return nil, err
		}
		_, err = io.Copy(hashImpl, file)
		if err != nil {
			log.WithFields(log.Fields{
				"err": err, "path": path, "method": hashKey,
			}).Error("Failed to load date into Hash")
			return nil, err
		}
		pathHash := hex.EncodeToString(hashImpl.Sum(nil))
		log.WithFields(log.Fields{
			"path":    path,
			"method":  hashKey,
			"value":   pathHash,
			"matches": expectedHash == pathHash,
		}).Info("Checksum Generated.")
		if expectedHash == pathHash {
			result.Valid = append(result.Valid, hashKey)
		} else {
			result.Invalid = append(result.Invalid, hashKey)
		}
	}
	return result, nil
}

func hashToHexDecStr(hash []byte) string {
	return hex.EncodeToString(hash)
}
