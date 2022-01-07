package tls

import (
	"crypto/tls"
	"errors"
	"os"
	"path"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type (
	Configuration struct {
		configuration tls.Config
		Error         error
	}
)

const (
	DefaultProtocol              string = "http/1.1"
	DefaultCertificatesCachePath string = "certificates"
)

const (
	Version10 int = iota
	Version11
	Version12
	Version13
)

var (
	legacyCipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	tls12CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	defaultNextProtocols = []string{
		DefaultProtocol, acme.ALPNProto,
	}
)

var (
	ErrConfigurationAutoNoDomains = errors.New("you must set at least one domain for tls certificate generation")
	ErrNewUnknownVersion          = errors.New("you must use valid tls version from go's crypto/tls package")
	ErrNewLegacyMode              = errors.New("you selected legacy tls version")
)

func New(tlsVersion int) (c *Configuration) {
	c = new(Configuration)

	c.configuration.ClientAuth = tls.VerifyClientCertIfGiven
	c.configuration.Renegotiation = tls.RenegotiateOnceAsClient

	c.configuration.MaxVersion = tls.VersionTLS13

	switch tlsVersion {
	case Version13:
		c.configuration.MinVersion = tls.VersionTLS13
	case Version12:
		c.configuration.MinVersion = tls.VersionTLS12
		c.configuration.CipherSuites = tls12CipherSuites
	case Version11:
		c.Error = ErrNewLegacyMode
		c.configuration.MinVersion = tls.VersionTLS11
		c.configuration.CipherSuites = legacyCipherSuites
	case Version10:
		c.Error = ErrNewLegacyMode
		c.configuration.MinVersion = tls.VersionTLS10
		c.configuration.CipherSuites = legacyCipherSuites
	default:
		c.Error = ErrNewUnknownVersion
		return
	}

	return
}

func (c *Configuration) AddCertificate(certificatePath, keyPath string) {
	ready, err := tls.LoadX509KeyPair(certificatePath, keyPath)

	if err != nil {
		c.Error = err
		return
	}

	c.configuration.Certificates = append(c.configuration.Certificates, ready)
	return
}

func (c *Configuration) AddEmbededCertificate(certificate, key []byte) (err error) {
	ready, err := tls.X509KeyPair(certificate, key)

	if err != nil {
		c.Error = err
		return
	}

	c.configuration.Certificates = append(c.configuration.Certificates, ready)
	return
}

func (c *Configuration) Default() (configuration *tls.Config) {
	configuration = c.configuration.Clone()

	return
}

func (c *Configuration) Auto(email, certificatesCachePath string, hosts ...string) (configuration *tls.Config) {
	if len(hosts) < 1 {
		c.Error = ErrConfigurationAutoNoDomains
		return
	}

	if certificatesCachePath == "" {
		certificatesCachePath = DefaultCertificatesCachePath
	}

	executable, err := os.Executable()

	if err != nil {
		c.Error = err
		return
	}

	directory := path.Dir(executable)
	cache := path.Join(directory, certificatesCachePath)

	manager := new(autocert.Manager)
	manager.Prompt = autocert.AcceptTOS
	manager.Cache = autocert.DirCache(cache)
	manager.HostPolicy = autocert.HostWhitelist(hosts...)
	manager.Email = email

	configuration = c.configuration.Clone()
	configuration.GetCertificate = manager.GetCertificate
	configuration.NextProtos = defaultNextProtocols

	return
}
