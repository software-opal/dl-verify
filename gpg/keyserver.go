package gpg

import (
	"context"
	"errors"
	"math/rand"
	"mime"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/net/context/ctxhttp"
)

type nonFatalError error

var (
	// ErrKeyNotFound is returned when the requested key does not exist on the
	// server.
	ErrKeyNotFound = nonFatalError(errors.New("sSpecified key was not found on server"))

	// ErrUnexpectedContentType is returned when the server sets an invalid
	// Content-Type in its response.
	ErrUnexpectedContentType = nonFatalError(errors.New("server did not return the expected content type"))

	// ErrMultipleKeysReturned is returned when a keyserver returns more than 1
	// key, meaning the KeyID/Fingerprint is being reused which is bad.
	ErrMultipleKeysReturned = errors.New("server returned multiple keys, verify the given key, key id and fingerprint")
)

// KeyServerInformation stores information about the key servers to use.
type KeyServerInformation struct {
	KeyServers []string
	UseHTTP    bool
	UseHTTPS   bool
	UseHKP     bool
	UseHkps    bool
	// FIXME: Actually support HKPS at some point.
}

func getDefaultKeyServers() []string {
	return []string{
		// "keys.gnupg.net",
		"pgp.mit.edu",
		// "keyserver.ubuntu.com",
		// "pgp.net.nz",
		// "ha.pool.sks-keyservers.net",
	}
}

// DefaultKeyServerInformation creates a KeyServerInformation with sane defaults
func DefaultKeyServerInformation() KeyServerInformation {
	return KeyServerInformation{
		KeyServers: getDefaultKeyServers(),
		UseHTTPS:   true,
		// HKP & HTTP will be used as a fallback in the event all HTTPS requests fail.
		// E.G. no SSL certs.
		// UseHKP:  true,
		// UseHTTP: true,
	}
}

// AddDefaultKeyServers adds the default keyservers into
// the KeyServerInformation if they're not already present.
func (ksi *KeyServerInformation) AddDefaultKeyServers() *KeyServerInformation {
	ksMap := make(map[string]bool)
	ksNew := make([]string, 0)
	for _, ks := range append(ksi.KeyServers, getDefaultKeyServers()...) {
		if !ksMap[ks] {
			ksMap[ks] = true
			ksNew = append(ksNew, ks)
		}
	}
	copy(ksi.KeyServers, ksNew)
	return ksi
}

// KeyServerURLs returns the URLs for the key servers as configured.
func (ksi *KeyServerInformation) KeyServerURLs() []url.URL {
	numProtocols := 0
	if ksi.UseHTTPS {
		numProtocols++
	}
	if ksi.UseHKP {
		numProtocols++
	}
	if ksi.UseHTTP {
		numProtocols++
	}
	if numProtocols == 0 {
		// Oops, no protocols
		return []url.URL{}
	}
	numKeyServers := len(ksi.KeyServers)
	outputKeySevers := make([]url.URL, numProtocols*numKeyServers)
	for src, target := range rand.Perm(numKeyServers) {
		keyServer := ksi.KeyServers[src]
		offset := 0
		// Here we ensure that we attempt HTTPS, then HKP, then HTTP, in that order.
		// trying all servers on one protocol before moving onto the next.
		if ksi.UseHTTPS {
			outputKeySevers[offset+target] = url.URL{
				Scheme: "https",
				Host:   keyServer,
			}
			offset += numKeyServers
		}
		if ksi.UseHKP {
			outputKeySevers[offset+target] = url.URL{
				Scheme: "http",
				// Append the HKP port.
				Host: keyServer + ":11371",
			}
			offset += numKeyServers
		}
		if ksi.UseHTTP {
			outputKeySevers[offset+target] = url.URL{
				Scheme: "http",
				Host:   keyServer,
			}
			// offset += numKeyServers
		}
	}
	return outputKeySevers
}

// DownloadKey downloads and verifies the key using the given key servers.
func (ksi *KeyServerInformation) DownloadKey(ctx context.Context, key *KeyID, client *http.Client) (*packet.PublicKey, error) {
	if ctx == nil {
		panic("context nil")
	} else if key == nil {
		panic("keyID nil")
	}
	key, err := key.Clean()
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{}
	}

	queryParams := url.Values(map[string][]string{
		"op":      {"get"},
		"search":  {"0X" + string(*key)},
		"exact":   {"on"},
		"options": {"mr"}, // Return the key in a machine readable format(i.e. without surrounding HTML)
	}).Encode()
	var entity *openpgp.Entity
	var nonFatalErr nonFatalError
	for _, serverURL := range ksi.KeyServerURLs() {
		serverURL.Path = "/pks/lookup"
		serverURL.RawQuery = queryParams
		entity, nonFatalErr, err = downloadKeyFromKeyServer(ctx, serverURL, client)
		if err != nil {
			return nil, err
		} else if nonFatalErr != nil {
			log.WithError(
				nonFatalErr,
			).WithField(
				"url", serverURL,
			).Info("Download failed, trying another server")
		} else if entity != nil {
			break
		}
	}
	if nonFatalErr != nil {
		log.WithError(
			nonFatalErr,
		).Error("All servers failed to provide key.")
		// It's now a fatal error because we couldn't get the key.
		return nil, nonFatalErr
	}
	return entity.PrimaryKey, nil
}

func downloadKeyFromKeyServer(ctx context.Context, url url.URL, client *http.Client) (*openpgp.Entity, nonFatalError, error) {
	if ctx == nil {
		panic("context nil")
	} else if client == nil {
		panic("client nil")
	}
	resp, err := ctxhttp.Get(ctx, client, url.String())
	if err != nil {
		return nil, nonFatalError(err), nil
	}
	defer resp.Body.Close()
	{
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return nil, ErrKeyNotFound, nil
		}
		mediatype, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil {
			return nil, nonFatalError(err), nil
		} else if mediatype != "application/pgp-keys" {
			return nil, ErrUnexpectedContentType, nil
		}
	}
	keyring, _ := openpgp.ReadArmoredKeyRing(resp.Body)
	if len(keyring) == 0 {
		return nil, ErrKeyNotFound, nil
	} else if len(keyring) > 1 {
		return nil, nil, ErrMultipleKeysReturned
	}
	key := keyring[0]
	return key, nil, nil
}
