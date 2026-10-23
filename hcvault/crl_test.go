package hcvault

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPKI bundles a CA, a leaf certificate signed by it, and helpers to build
// CRLs, for exercising the CRL verification logic without a live Vault server.
type testPKI struct {
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
}

// issueCert generates a key and certificate for cn with the given serial. Can
// be a CA or leaf dependening on isCa flag. is self-signed when parent is nil
func issueCert(
	t *testing.T,
	cn string,
	serial int64,
	isCA bool,
	parent *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		tmpl.BasicConstraintsValid = true
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{cn}
	}

	signer, signerKey := tmpl, key // self-signed by default
	if parent != nil {
		signer, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()

	caCert, caKey := issueCert(t, "Test Vault CA", 1, true, nil, nil)
	leaf, leafKey := issueCert(t, "vault.example.com", 42, false, caCert, caKey)

	return &testPKI{caCert: caCert, caKey: caKey, leaf: leaf, leafKey: leafKey}
}

// crl builds a CRL signed by the CA, revoking the given serial numbers.
func (p *testPKI) crl(t *testing.T, serials ...*big.Int) *x509.RevocationList {
	t.Helper()
	return crlSignedBy(t, p.caCert, p.caKey, serials...)
}

// expiredCRL builds a CRL signed by the CA whose NextUpdate is in the past,
// revoking the given serial numbers.
func (p *testPKI) expiredCRL(t *testing.T, serials ...*big.Int) *x509.RevocationList {
	t.Helper()
	now := time.Now()
	return buildCRL(t, p.caCert, p.caKey, now.Add(-2*time.Hour), now.Add(-time.Hour), serials...)
}

// notYetValidCRL builds a CRL signed by the CA whose ThisUpdate is in the
// future, so it is not yet in effect, revoking the given serial numbers.
func (p *testPKI) notYetValidCRL(t *testing.T, serials ...*big.Int) *x509.RevocationList {
	t.Helper()
	now := time.Now()
	return buildCRL(t, p.caCert, p.caKey, now.Add(time.Hour), now.Add(2*time.Hour), serials...)
}

// verifiedChain mimics the verifiedChains argument TLS passes to
// VerifyPeerCertificate: leaf first, issuer second.
func (p *testPKI) verifiedChain() [][]*x509.Certificate {
	return [][]*x509.Certificate{{p.leaf, p.caCert}}
}

func pemCRL(t *testing.T, crl *x509.RevocationList) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl.Raw})
}

// testChainPKI bundles a root CA, an intermediate CA signed by the root, and a
// leaf signed by the intermediate. It exercises full-chain CRL verification
// where revocation may apply to the leaf and/or the intermediate.
type testChainPKI struct {
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	intCert  *x509.Certificate
	intKey   *ecdsa.PrivateKey
	leaf     *x509.Certificate
	leafKey  *ecdsa.PrivateKey
}

func newTestChainPKI(t *testing.T) *testChainPKI {
	t.Helper()

	rootCert, rootKey := issueCert(t, "Test Root CA", 1, true, nil, nil)
	intCert, intKey := issueCert(t, "Test Intermediate CA", 2, true, rootCert, rootKey)
	leaf, leafKey := issueCert(t, "vault.example.com", 42, false, intCert, intKey)

	return &testChainPKI{
		rootCert: rootCert, rootKey: rootKey,
		intCert: intCert, intKey: intKey,
		leaf: leaf, leafKey: leafKey,
	}
}

// verifiedChain mimics the verifiedChains argument TLS passes to
// VerifyPeerCertificate for a three-level chain: leaf, intermediate, root.
func (p *testChainPKI) verifiedChain() [][]*x509.Certificate {
	return [][]*x509.Certificate{{p.leaf, p.intCert, p.rootCert}}
}

// buildCRL builds a CRL signed by the given issuer/key with explicit validity
// window, revoking the given serial numbers.
func buildCRL(
	t *testing.T,
	issuer *x509.Certificate,
	key *ecdsa.PrivateKey,
	thisUpdate, nextUpdate time.Time,
	serials ...*big.Int,
) *x509.RevocationList {
	t.Helper()

	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   s,
			RevocationTime: thisUpdate,
		})
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	return crl
}

// crlSignedBy builds a CRL signed by the given issuer/key,
// revoking the given serial numbers.
func crlSignedBy(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, serials ...*big.Int) *x509.RevocationList {
	t.Helper()
	now := time.Now()
	return buildCRL(t, issuer, key, now.Add(-time.Minute), now.Add(time.Hour), serials...)
}

// leafCRL builds the CRL for the leaf, signed by the intermediate.
func (p *testChainPKI) leafCRL(t *testing.T, serials ...*big.Int) *x509.RevocationList {
	t.Helper()
	return crlSignedBy(t, p.intCert, p.intKey, serials...)
}

// intCRL builds the CRL for the intermediate, signed by the root.
func (p *testChainPKI) intCRL(t *testing.T, serials ...*big.Int) *x509.RevocationList {
	t.Helper()
	return crlSignedBy(t, p.rootCert, p.rootKey, serials...)
}

func TestGetCRLFiles(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv(SopsHCVaultCRLFile, "")
		os.Unsetenv(SopsHCVaultCRLFile)
		paths, err := getCRLFiles()
		assert.NoError(t, err)
		assert.Nil(t, paths)
	})

	t.Run("empty value", func(t *testing.T) {
		t.Setenv(SopsHCVaultCRLFile, "   ")
		paths, err := getCRLFiles()
		assert.NoError(t, err)
		assert.Nil(t, paths)
	})

	t.Run("single path", func(t *testing.T) {
		t.Setenv(SopsHCVaultCRLFile, "/tmp/a.crl")
		paths, err := getCRLFiles()
		assert.NoError(t, err)
		assert.Equal(t, []string{"/tmp/a.crl"}, paths)
	})

	t.Run("multiple paths trimmed", func(t *testing.T) {
		t.Setenv(SopsHCVaultCRLFile, " /tmp/a.crl , /tmp/b.crl ")
		paths, err := getCRLFiles()
		assert.NoError(t, err)
		assert.Equal(t, []string{"/tmp/a.crl", "/tmp/b.crl"}, paths)
	})

	t.Run("empty entry errors", func(t *testing.T) {
		t.Setenv(SopsHCVaultCRLFile, "/tmp/a.crl,,")
		paths, err := getCRLFiles()
		assert.Error(t, err)
		assert.Nil(t, paths)
	})
}

func TestParseCRLs(t *testing.T) {
	pki := newTestPKI(t)
	crl := pki.crl(t, big.NewInt(42))

	t.Run("PEM", func(t *testing.T) {
		got, err := parseCRLs(pemCRL(t, crl))
		assert.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, crl.Number, got[0].Number)
	})

	t.Run("DER", func(t *testing.T) {
		got, err := parseCRLs(crl.Raw)
		assert.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, crl.Number, got[0].Number)
	})

	t.Run("invalid", func(t *testing.T) {
		got, err := parseCRLs([]byte("not a crl"))
		assert.Error(t, err)
		assert.Nil(t, got)
	})
}

func TestLoadCRLs(t *testing.T) {
	pki := newTestPKI(t)
	crl := pki.crl(t, big.NewInt(42))

	dir := t.TempDir()
	pemPath := filepath.Join(dir, "revoked.pem")
	require.NoError(t, os.WriteFile(pemPath, pemCRL(t, crl), 0o600))

	t.Run("loads file", func(t *testing.T) {
		got, err := loadCRLs([]string{pemPath})
		assert.NoError(t, err)
		assert.Len(t, got, 1)
	})

	t.Run("missing file errors", func(t *testing.T) {
		got, err := loadCRLs([]string{filepath.Join(dir, "nope.pem")})
		assert.Error(t, err)
		assert.Nil(t, got)
	})

	t.Run("garbage file errors", func(t *testing.T) {
		badPath := filepath.Join(dir, "bad.pem")
		require.NoError(t, os.WriteFile(badPath, []byte("garbage"), 0o600))
		got, err := loadCRLs([]string{badPath})
		assert.Error(t, err)
		assert.Nil(t, got)
	})
}

func TestNewCRLVerifier(t *testing.T) {
	pki := newTestPKI(t)

	t.Run("not revoked passes", func(t *testing.T) {
		crl := pki.crl(t, big.NewInt(999)) // some other serial
		verify := newCRLVerifier([]*x509.RevocationList{crl})
		err := verify(nil, pki.verifiedChain())
		assert.NoError(t, err)
	})

	t.Run("revoked rejected", func(t *testing.T) {
		crl := pki.crl(t, pki.leaf.SerialNumber)
		verify := newCRLVerifier([]*x509.RevocationList{crl})
		err := verify(nil, pki.verifiedChain())
		assert.Error(t, err)
		assert.ErrorContains(t, err, "has been revoked")
	})

	t.Run("no applicable CRL rejected (hard-fail)", func(t *testing.T) {
		// CRL signed by a different, unrelated CA -> signature does not
		// verify against the leaf's issuer, so it is not applicable.
		other := newTestPKI(t)
		crl := other.crl(t, pki.leaf.SerialNumber)
		verify := newCRLVerifier([]*x509.RevocationList{crl})
		err := verify(nil, pki.verifiedChain())
		assert.Error(t, err)
		assert.ErrorContains(t, err, "no valid CRL found for issuer")
	})

	t.Run("no verified chain rejected", func(t *testing.T) {
		crl := pki.crl(t, big.NewInt(999))
		verify := newCRLVerifier([]*x509.RevocationList{crl})
		err := verify(nil, nil)
		assert.Error(t, err)
	})

	t.Run("expired CRL rejected (hard-fail)", func(t *testing.T) {
		// A CRL whose NextUpdate is in the past must not be relied upon,
		// even if it does not list the leaf. Under hard-fail, having no
		// unexpired applicable CRL is a rejection.
		crl := pki.expiredCRL(t, big.NewInt(999))
		verify := newCRLVerifier([]*x509.RevocationList{crl})
		err := verify(nil, pki.verifiedChain())
		assert.Error(t, err)
		assert.ErrorContains(t, err, "no valid CRL found for issuer")
	})

	t.Run("not-yet-valid CRL rejected (hard-fail)", func(t *testing.T) {
		// A CRL whose ThisUpdate is in the future is not in effect yet and
		// must not be relied upon. Under hard-fail, having no applicable
		// in-effect CRL is a rejection.
		crl := pki.notYetValidCRL(t, big.NewInt(999))
		verify := newCRLVerifier([]*x509.RevocationList{crl})
		err := verify(nil, pki.verifiedChain())
		assert.Error(t, err)
		assert.ErrorContains(t, err, "no valid CRL found for issuer")
	})
}

func TestNewCRLVerifierFullChain(t *testing.T) {
	pki := newTestChainPKI(t)

	t.Run("leaf and intermediate both covered and not revoked passes", func(t *testing.T) {
		crls := []*x509.RevocationList{
			pki.leafCRL(t, big.NewInt(999)),
			pki.intCRL(t, big.NewInt(999)),
		}
		verify := newCRLVerifier(crls)
		err := verify(nil, pki.verifiedChain())
		assert.NoError(t, err)
	})

	t.Run("revoked leaf rejected", func(t *testing.T) {
		crls := []*x509.RevocationList{
			pki.leafCRL(t, pki.leaf.SerialNumber),
			pki.intCRL(t, big.NewInt(999)),
		}
		verify := newCRLVerifier(crls)
		err := verify(nil, pki.verifiedChain())
		assert.Error(t, err)
		assert.ErrorContains(t, err, "has been revoked")
	})

	t.Run("revoked intermediate rejected", func(t *testing.T) {
		// The leaf itself is not listed, but its issuing intermediate CA is
		// revoked by the root. Full-chain verification must catch this.
		crls := []*x509.RevocationList{
			pki.leafCRL(t, big.NewInt(999)),
			pki.intCRL(t, pki.intCert.SerialNumber),
		}
		verify := newCRLVerifier(crls)
		err := verify(nil, pki.verifiedChain())
		assert.Error(t, err)
		assert.ErrorContains(t, err, "has been revoked")
		assert.ErrorContains(t, err, pki.intCert.Subject.CommonName)
	})

	t.Run("missing CRL for intermediate rejected (hard-fail)", func(t *testing.T) {
		// Only the leaf CRL is supplied; the intermediate has no applicable
		// CRL, so under hard-fail the connection is rejected.
		crls := []*x509.RevocationList{pki.leafCRL(t, big.NewInt(999))}
		verify := newCRLVerifier(crls)
		err := verify(nil, pki.verifiedChain())
		assert.Error(t, err)
		assert.ErrorContains(t, err, "no valid CRL found for issuer")
	})

	t.Run("missing CRL for leaf rejected (hard-fail)", func(t *testing.T) {
		// Only the intermediate CRL is supplied; the leaf has no applicable
		// CRL.
		crls := []*x509.RevocationList{pki.intCRL(t, big.NewInt(999))}
		verify := newCRLVerifier(crls)
		err := verify(nil, pki.verifiedChain())
		assert.Error(t, err)
		assert.ErrorContains(t, err, "no valid CRL found for issuer")
	})
}

func TestApplyCRLToClient(t *testing.T) {
	pki := newTestPKI(t)
	crls := []*x509.RevocationList{pki.crl(t, big.NewInt(999))}

	t.Run("nil client yields configured client", func(t *testing.T) {
		got, err := applyCRLToClient(nil, crls)
		require.NoError(t, err)
		require.NotNil(t, got)
		tr, ok := got.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, tr.TLSClientConfig)
		assert.NotNil(t, tr.TLSClientConfig.VerifyPeerCertificate)
	})

	t.Run("does not mutate caller", func(t *testing.T) {
		callerTransport := &http.Transport{}
		caller := &http.Client{Transport: callerTransport}
		got, err := applyCRLToClient(caller, crls)
		require.NoError(t, err)
		assert.NotSame(t, caller, got)
		// The returned client must use a cloned transport, not the caller's.
		gotTransport, ok := got.Transport.(*http.Transport)
		require.True(t, ok)
		assert.NotSame(t, callerTransport, gotTransport)
		// Our verifier lives only on the clone's TLS config.
		require.NotNil(t, gotTransport.TLSClientConfig)
		assert.NotNil(t, gotTransport.TLSClientConfig.VerifyPeerCertificate)
	})

	t.Run("preserves and chains existing VerifyPeerCertificate", func(t *testing.T) {
		called := false
		caller := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
					called = true
					return nil
				},
			},
		}}
		got, err := applyCRLToClient(caller, crls)
		require.NoError(t, err)
		tr := got.Transport.(*http.Transport)
		err = tr.TLSClientConfig.VerifyPeerCertificate(nil, pki.verifiedChain())
		assert.NoError(t, err)
		assert.True(t, called, "caller's VerifyPeerCertificate should run")
	})

	t.Run("caller VerifyPeerCertificate failure short-circuits CRL check", func(t *testing.T) {
		// When the caller's verifier fails, its error must propagate and the
		// CRL check must not run. We prove the CRL check did not run by
		// passing a chain whose leaf is revoked by crls: if the CRL check had
		// executed it would surface a "has been revoked" error instead of the
		// caller's error.
		revokedCRL := []*x509.RevocationList{pki.crl(t, pki.leaf.SerialNumber)}
		caller := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				VerifyPeerCertificate: func([][]byte, [][]*x509.Certificate) error {
					return assert.AnError
				},
			},
		}}
		got, err := applyCRLToClient(caller, revokedCRL)
		require.NoError(t, err)
		tr := got.Transport.(*http.Transport)
		err = tr.TLSClientConfig.VerifyPeerCertificate(nil, pki.verifiedChain())
		require.Error(t, err)
		assert.ErrorIs(t, err, assert.AnError, "caller's error must propagate")
		assert.NotContains(t, err.Error(), "has been revoked",
			"CRL check must not run after caller's verifier fails")
	})

	t.Run("non-standard transport errors", func(t *testing.T) {
		caller := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, nil
		})}
		got, err := applyCRLToClient(caller, crls)
		assert.Error(t, err)
		assert.Nil(t, got)
	})
}

func TestConfigureCRL(t *testing.T) {
	pki := newTestPKI(t)
	dir := t.TempDir()
	crlPath := filepath.Join(dir, "revoked.pem")
	require.NoError(t, os.WriteFile(crlPath, pemCRL(t, pki.crl(t, big.NewInt(999))), 0o600))

	t.Run("unset is passthrough", func(t *testing.T) {
		os.Unsetenv(SopsHCVaultCRLFile)
		in := &http.Client{}
		base := &http.Client{}
		got, err := configureCRL("https://vault.example.com", in, base)
		assert.NoError(t, err)
		assert.Same(t, in, got)
	})

	t.Run("http address errors", func(t *testing.T) {
		t.Setenv(SopsHCVaultCRLFile, crlPath)
		in := &http.Client{}
		base := &http.Client{}
		got, err := configureCRL("http://127.0.0.1:8200", in, base)
		assert.Error(t, err, "CRL must hard-fail on plaintext http")
		assert.Nil(t, got)
	})

	t.Run("https address configures CRL", func(t *testing.T) {
		t.Setenv(SopsHCVaultCRLFile, crlPath)
		base := &http.Client{}
		got, err := configureCRL("https://vault.example.com", nil, base)
		require.NoError(t, err)
		require.NotNil(t, got)
		tr, ok := got.Transport.(*http.Transport)
		require.True(t, ok)
		assert.NotNil(t, tr.TLSClientConfig.VerifyPeerCertificate)
	})

	t.Run("preserves base TLS config when no client injected", func(t *testing.T) {
		t.Setenv(SopsHCVaultCRLFile, crlPath)

		// Simulate the client the Vault API configures from its environment:
		// a custom CA pool and server name, as VAULT_CACERT /
		// VAULT_TLS_SERVER_NAME would produce.
		rootPool := x509.NewCertPool()
		rootPool.AddCert(pki.caCert)
		base := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    rootPool,
				ServerName: "vault.example.com",
				MinVersion: tls.VersionTLS12,
			},
		}}

		got, err := configureCRL("https://vault.example.com", nil, base)
		require.NoError(t, err)
		require.NotNil(t, got)
		tr, ok := got.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, tr.TLSClientConfig)

		// The CRL verifier must be installed...
		assert.NotNil(t, tr.TLSClientConfig.VerifyPeerCertificate)
		// ...without discarding the base's env-derived TLS settings.
		assert.Equal(t, "vault.example.com", tr.TLSClientConfig.ServerName)
		assert.Equal(t, uint16(tls.VersionTLS12), tr.TLSClientConfig.MinVersion)
		require.NotNil(t, tr.TLSClientConfig.RootCAs)
		assert.True(t, tr.TLSClientConfig.RootCAs.Equal(rootPool),
			"custom CA pool from the base client must be preserved")

		// The base client must not be mutated.
		assert.NotSame(t, base, got)
		assert.Nil(t, base.Transport.(*http.Transport).TLSClientConfig.VerifyPeerCertificate,
			"base client's TLS config must not be modified")
	})

	t.Run("bad path errors eagerly", func(t *testing.T) {
		t.Setenv(SopsHCVaultCRLFile, filepath.Join(dir, "missing.pem"))
		got, err := configureCRL("https://vault.example.com", nil, &http.Client{})
		assert.Error(t, err)
		assert.Nil(t, got)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
