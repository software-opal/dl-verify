package gpg

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// KeyLength indicates minimum key length accepted by NewCleanedKeyID
type KeyLength int

const (
	// KeyID32BitLength is the hexadecimal length of a 32-bit KeyID.
	KeyID32BitLength KeyLength = 8
	// KeyID64BitLength is the hexadecimal length of a 64-bit KeyID.
	KeyID64BitLength KeyLength = 16
	// FingerprintVersion3Length is the hexadecimal length of a Version 3 fingerprint.
	FingerprintVersion3Length KeyLength = 32
	// FingerprintVersion4Length is the hexadecimal length of a Version 4 fingerprint.
	FingerprintVersion4Length KeyLength = 40
)

// ErrGpgKeyInsecure indicates the key is a 32 or a 64-bit key when the
// opts disabling security are not given.
type ErrGpgKeyInsecure struct {
	Key string
}

func (e ErrGpgKeyInsecure) Error() string {
	keyLen := len(e.Key)
	seeAlso := ""
	if keyLen == int(KeyID32BitLength) {
		seeAlso = ". See also https://evil32.com/"
	}
	return fmt.Sprintf("%d-bit keys are not supported%s", keyLen, seeAlso)
}

// ErrGpgKeyInvalid indicates the key of an invalid length or invalid
// characters
type ErrGpgKeyInvalid struct {
	Key           string
	InvalidReason string
}

func (e ErrGpgKeyInvalid) Error() string {
	return fmt.Sprintf("Given key is not valid. Reason: %s", e.InvalidReason)
}

// KeyID is a validated GPG key.
type KeyID string

// NewKeyID creates a KeyID object after verifying the key string for validity
//  and security(Version 3 fingerprints and above.).
func NewKeyID(keyID string) (*KeyID, error) {
	return NewCleanedKeyID(keyID, FingerprintVersion3Length)
}

func (key *KeyID) Clean() (*KeyID, error) {
	return NewCleanedKeyID(string(*key), KeyID32BitLength)
}

// NewCleanedKeyID creates a KeyID object after verifying the key string for
// validity and security.
func NewCleanedKeyID(originalKeyID string, minLengthForSecurity KeyLength) (*KeyID, error) {
	// Remove spaces & colons from keyID -- https://stackoverflow.com/a/32081891/369021
	keyID := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.IsPunct(r) {
			return -1
		}
		return r
	}, originalKeyID)
	keyID = strings.ToUpper(keyID)
	if keyID[0:2] == "0X" {
		// Remove the prefixing '0X' if it is present.
		keyID = keyID[2:]
	}
	if _, err := hex.DecodeString(keyID); err != nil {
		return nil, ErrGpgKeyInvalid{
			Key:           keyID,
			InvalidReason: "Key not Hexadecimal",
		}
	}
	if len(keyID)%2 == 1 && keyID[0] == '0' {
		// Keys are always even; so it's probably got a prefixed '0'; remove it.
		keyID = keyID[1:]
	}
	length := KeyLength(len(keyID))
	if length != KeyID32BitLength &&
		length != KeyID64BitLength &&
		length != FingerprintVersion3Length &&
		length != FingerprintVersion4Length {
		return nil, ErrGpgKeyInvalid{
			Key:           keyID,
			InvalidReason: "Key not a supported length",
		}
	}
	if length < minLengthForSecurity {
		return nil, ErrGpgKeyInsecure{
			Key: keyID,
		}
	}
	key := KeyID(keyID)
	return &key, nil
}
