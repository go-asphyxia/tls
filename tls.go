package tls

import (
	"crypto/tls"
	"errors"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type (
	TLS struct {
		TLSConfiguration *tls.Config
	}
)

const (
	DefaultProtocol              string = "http/1.1"
	DefaultCertificatesCachePath string = "certificatesCache"
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
	ErrTLSAutoNoDomains     = errors.New("you must set at least one domain for tls certificate generation")
	ErrNewTLSUnknownVersion = errors.New("NewTLS: unknown version")
	ErrNewTLSLegacyMode     = errors.New("NewTLS: legacy mode")
)

func NewTLS(tlsVersion int) (t *TLS, err error) {
	t = &TLS{
		TLSConfiguration: &tls.Config{
			ClientAuth:    tls.VerifyClientCertIfGiven,
			Renegotiation: tls.RenegotiateOnceAsClient,
			MaxVersion:    tls.VersionTLS13,
		},
	}

	switch tlsVersion {
	case Version13:
		t.TLSConfiguration.MinVersion = tls.VersionTLS13
	case Version12:
		t.TLSConfiguration.MinVersion = tls.VersionTLS12
		t.TLSConfiguration.CipherSuites = tls12CipherSuites
	case Version11:
		err = ErrNewTLSLegacyMode
		t.TLSConfiguration.MinVersion = tls.VersionTLS11
		t.TLSConfiguration.CipherSuites = legacyCipherSuites
	case Version10:
		err = ErrNewTLSLegacyMode
		t.TLSConfiguration.MinVersion = tls.VersionTLS10
		t.TLSConfiguration.CipherSuites = legacyCipherSuites
	default:
		err = ErrNewTLSUnknownVersion
	}

	return
}

func (t *TLS) AddCertificate(certificatePath, keyPath string) (err error) {
	ready, err := tls.LoadX509KeyPair(certificatePath, keyPath)

	if err != nil {
		return
	}

	t.TLSConfiguration.Certificates = append(t.TLSConfiguration.Certificates, ready)
	return
}

func (t *TLS) AddEmbededCertificate(certificate, key []byte) (err error) {
	ready, err := tls.X509KeyPair(certificate, key)

	if err != nil {
		return
	}

	t.TLSConfiguration.Certificates = append(t.TLSConfiguration.Certificates, ready)
	return
}

func (t *TLS) Clone() (tlsConfiguration *tls.Config) {
	tlsConfiguration = t.TLSConfiguration.Clone()
	return
}

func (t *TLS) Auto(email, certificatesCachePath string, hosts ...string) (tlsConfiguration *tls.Config, err error) {
	if len(hosts) < 1 {
		err = ErrTLSAutoNoDomains
		return
	}

	if certificatesCachePath == "" {
		certificatesCachePath = DefaultCertificatesCachePath
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(certificatesCachePath),
		HostPolicy: autocert.HostWhitelist(hosts...),
		Email:      email,
	}

	tlsConfiguration = t.TLSConfiguration.Clone()
	tlsConfiguration.GetCertificate = manager.GetCertificate
	tlsConfiguration.NextProtos = defaultNextProtocols

	return
}
