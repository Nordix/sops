package hcvault

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// SopsHCVaultCRLFile can be set as an environment variable with a
	// comma-separated list of CRL file paths as value. Checks every
	// non-root certificate in the Vault server's chain against a
	// currently valid CRL.
	SopsHCVaultCRLFile = "SOPS_HC_VAULT_CRL_FILE"
)

// getCRLFiles returns the list of CRL file paths configured through the
// SopsHCVaultCRLFile environment variable. Empty comma separated values are
// treated as a configuration error.
func getCRLFiles() ([]string, error) {
	value, ok := os.LookupEnv(SopsHCVaultCRLFile)
	if !ok || strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	paths := make([]string, 0, len(parts))
	for idx, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("%s's entry %d is empty", SopsHCVaultCRLFile, idx+1)
		}
		paths = append(paths, p)
	}
	return paths, nil
}

// loadCRLs reads and parses the CRLs from the provided file paths. Each file
// may contain a PEM-encoded ("X509 CRL") or DER-encoded CRL.
func loadCRLs(paths []string) ([]*x509.RevocationList, error) {
	var crls []*x509.RevocationList
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("cannot read CRL file %q: %w", p, err)
		}
		parsed, err := parseCRLs(data)
		if err != nil {
			return nil, fmt.Errorf("cannot parse CRL file %q: %w", p, err)
		}
		if len(parsed) == 0 {
			return nil, fmt.Errorf("CRL file %q does not contain a certificate revocation list", p)
		}
		crls = append(crls, parsed...)
	}
	return crls, nil
}

// parseCRLs parses one or more CRLs from the given bytes. It supports
// PEM-encoded input (possibly containing multiple "X509 CRL" blocks) as well
// as a single DER-encoded CRL.
func parseCRLs(data []byte) ([]*x509.RevocationList, error) {
	var crls []*x509.RevocationList

	// Attempt PEM decoding first; fall back to raw DER if no PEM blocks are
	// present.
	rest := data
	foundPEM := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		foundPEM = true
		if block.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, err
		}
		crls = append(crls, crl)
	}
	if foundPEM {
		return crls, nil
	}

	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, err
	}
	return []*x509.RevocationList{crl}, nil
}

// newCRLVerifier checks every non-root certificate in the chain against a
// currently valid CRL signed by its direct issuer.
func newCRLVerifier(crls []*x509.RevocationList) func([][]byte, [][]*x509.Certificate) error {
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		chain, err := verifiedChainWithIssuer(verifiedChains)
		if err != nil {
			return err
		}

		now := time.Now()
		for i := 0; i < len(chain)-1; i++ {
			if err := verifyCertificateCRL(chain[i], chain[i+1], crls, now); err != nil {
				return err
			}
		}
		return nil
	}
}

func verifiedChainWithIssuer(chains [][]*x509.Certificate) ([]*x509.Certificate, error) {
	if len(chains) == 0 || len(chains[0]) < 2 {
		return nil, fmt.Errorf(
			"cannot perform CRL check: no verified certificate chain with an issuer",
		)
	}
	return chains[0], nil
}

func verifyCertificateCRL(
	cert, issuer *x509.Certificate,
	crls []*x509.RevocationList,
	now time.Time,
) error {
	applicable := findApplicableCRLs(crls, issuer, now)
	if len(applicable) == 0 {
		return fmt.Errorf(
			"no valid CRL found for issuer %q of vault server certificate chain (certificate %q)",
			issuer.Subject.CommonName,
			cert.Subject.CommonName,
		)
	}

	for _, crl := range applicable {
		if isCertificateRevoked(cert, crl) {
			return fmt.Errorf(
				"vault server certificate chain entry %q (serial %s) has been revoked",
				cert.Subject.CommonName,
				cert.SerialNumber,
			)
		}
	}
	return nil
}

func findApplicableCRLs(
	crls []*x509.RevocationList,
	issuer *x509.Certificate,
	now time.Time,
) []*x509.RevocationList {
	var applicable []*x509.RevocationList

	for _, crl := range crls {
		if crl.CheckSignatureFrom(issuer) != nil {
			continue
		}
		if !isCRLCurrentlyValid(crl, now) {
			continue
		}
		applicable = append(applicable, crl)
	}
	return applicable
}

func isCRLCurrentlyValid(crl *x509.RevocationList, now time.Time) bool {
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return false
	}
	return !now.Before(crl.ThisUpdate)
}

func isCertificateRevoked(cert *x509.Certificate, crl *x509.RevocationList) bool {
	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

// applyCRLToClient returns an *http.Client, derived from hc (or a sensible
// default when hc is nil), whose TLS configuration performs CRL checking of
// the Vault server's leaf certificate. If hc is provided, the values are not changed.
func applyCRLToClient(hc *http.Client, crls []*x509.RevocationList) (*http.Client, error) {
	var client http.Client
	var transport *http.Transport

	switch {
	case hc == nil:
		client = http.Client{}
		transport = http.DefaultTransport.(*http.Transport).Clone()
	default:
		client = *hc
		switch rt := hc.Transport.(type) {
		case nil:
			transport = http.DefaultTransport.(*http.Transport).Clone()
		case *http.Transport:
			transport = rt.Clone()
		default:
			return nil, fmt.Errorf("cannot enable CRL checking: injected HTTP client uses a non-standard transport (%T)", hc.Transport)
		}
	}

	var tlsConfig *tls.Config
	if transport.TLSClientConfig != nil {
		tlsConfig = transport.TLSClientConfig.Clone()
	} else {
		tlsConfig = &tls.Config{}
	}

	crlVerify := newCRLVerifier(crls)
	if existing := tlsConfig.VerifyPeerCertificate; existing != nil {
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if err := existing(rawCerts, verifiedChains); err != nil {
				return err
			}
			return crlVerify(rawCerts, verifiedChains)
		}
	} else {
		tlsConfig.VerifyPeerCertificate = crlVerify
	}

	transport.TLSClientConfig = tlsConfig
	client.Transport = transport
	return &client, nil
}

// configureCRL enables CRL checking when SopsHCVaultCRLFile is set.
// Requires an https Vault address. Layers verification onto hc if
// injected, otherwise base, preserving Vault's environment-derived TLS settings.
func configureCRL(address string, hc, base *http.Client) (*http.Client, error) {
	paths, err := getCRLFiles()
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return hc, nil
	}

	if !strings.HasPrefix(strings.ToLower(address), "https://") {
		return nil, fmt.Errorf(
			"%s is set but the Vault address %q is not an https:// endpoint; "+
				"CRL checking requires TLS", SopsHCVaultCRLFile, address)
	}

	crls, err := loadCRLs(paths)
	if err != nil {
		return nil, err
	}

	target := hc
	if target == nil {
		target = base
	}

	return applyCRLToClient(target, crls)
}
