package hcvault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"

	"github.com/getsops/sops/v3/logging"
)

const (
	// KeyTypeIdentifier is the string used to identify a Vault MasterKey.
	KeyTypeIdentifier = "hc_vault"
	// SopsHCVaultAllowlist can be set as an environment variable with a string list
	// of age keys as value.
	SopsHCVaultAllowlist = "SOPS_HC_VAULT_ALLOWLIST"
	// SopsHCVaultCRLFile can be set as an environment variable with a
	// comma-separated list of paths to Certificate Revocation List (CRL)
	// files, in PEM or DER encoding. When set, every certificate in the
	// Vault server's verified chain (except the trust anchor) is checked
	// against these CRLs during the TLS handshake, and the connection is
	// rejected if any of them has been revoked.
	//
	// CRL checking is opt-in and requires an https:// Vault address; setting
	// it against a plaintext http:// endpoint fails client construction. See
	// newCRLVerifier for the exact applicability and hard-fail rules.
	SopsHCVaultCRLFile = "SOPS_HC_VAULT_CRL_FILE"
	// Special value for allowlist that allows all hosts
	AllowlistAllHosts = "all"
	// Special value for allowlist that allows no hosts
	AllowlistNoHosts = "none"
	// Default value of allowlist. Should eventually be changed to "none".
	AllowlistDefault = AllowlistAllHosts
)

type allowList struct {
	All  bool
	URIs []string
}

func (al *allowList) Allows(address string) bool {
	if al.All {
		return true
	}
	if !strings.HasSuffix(address, "/") {
		address = address + "/"
	}
	for _, uri := range al.URIs {
		if strings.HasPrefix(address, uri) {
			return true
		}
	}
	return false
}

func parseAllowlistString(allowlistStr string) (allowList, error) {
	switch allowlistStr {
	case AllowlistAllHosts:
		return allowList{
			All:  true,
			URIs: nil,
		}, nil
	case AllowlistNoHosts:
		return allowList{
			All:  false,
			URIs: nil,
		}, nil
	}
	uris := strings.Split(allowlistStr, ",")
	for idx, uri := range uris {
		uri = strings.Trim(uri, " ")
		if uri == "" {
			return allowList{}, fmt.Errorf("%s's entry %d is empty", SopsHCVaultAllowlist, idx+1)
		}
		if !strings.HasSuffix(uri, "/") {
			uri = uri + "/"
		}
		uris[idx] = uri
	}
	return allowList{
		All:  false,
		URIs: uris,
	}, nil
}

func getAllowlist() (allowList, error) {
	var allowlistStr = AllowlistDefault
	if allowlist, ok := os.LookupEnv(SopsHCVaultAllowlist); ok && len(allowlist) > 0 {
		allowlistStr = allowlist
	}
	return parseAllowlistString(allowlistStr)
}

func init() {
	log = logging.NewLogger("VAULT_TRANSIT")
}

var (
	// log is the global logger for any Vault Transit MasterKey.
	log *logrus.Logger
	// vaultTTL is the duration after which a MasterKey requires rotation.
	vaultTTL = time.Hour * 24 * 30 * 6
	// defaultTokenFile is the name of the file in the user's home directory
	// where a Vault token is expected to be stored.
	defaultTokenFile = ".vault-token"
)

// Token used for authenticating towards a Vault server.
type Token string

// ApplyToMasterKey configures the token on the provided key.
func (t Token) ApplyToMasterKey(key *MasterKey) {
	key.token = string(t)
}

// MasterKey is a Vault Transit backend path used to Encrypt and Decrypt
// SOPS' data key.
type MasterKey struct {
	// VaultAddress is the address of the Vault server.
	VaultAddress string
	// EnginePath is the path to the Vault Transit Secret engine relative
	// to the VaultAddress.
	EnginePath string
	// KeyName is the name of the key in the Vault Transit engine.
	KeyName string
	// EncryptedKey contains the SOPS data key encrypted with the Vault Transit
	// key.
	EncryptedKey string
	// CreationDate of the MasterKey, used to determine if the EncryptedKey
	// needs rotation.
	CreationDate time.Time

	// token is the token used for authenticating against the VaultAddress
	// server. It can be injected by a (local) keyservice.KeyServiceServer
	// Token.ApplyToMasterKey. If empty, the default client configuration
	// is used, before falling back to the token stored in defaultTokenFile.
	token string
	// httpClient is used to override the default HTTP client used by the Vault client.
	httpClient *http.Client
}

// NewMasterKeysFromURIs creates a list of MasterKeys from a list of Vault
// URIs.
func NewMasterKeysFromURIs(uris string) ([]*MasterKey, error) {
	var keys []*MasterKey
	if uris == "" {
		return keys, nil
	}
	for _, uri := range strings.Split(uris, ",") {
		if uri == "" {
			continue
		}
		key, err := NewMasterKeyFromURI(uri)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// NewMasterKeyFromURI obtains the Vault address, Transit backend path and the
// key name from the full URI of the key.
func NewMasterKeyFromURI(uri string) (*MasterKey, error) {
	var key *MasterKey
	if uri == "" {
		return key, nil
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		return nil, fmt.Errorf("missing scheme in Vault URL (should be like this: +"+
			"https://vault.example.com:8200/v1/transit/keys/keyName), got: %v", uri)
	}
	enginePath, keyName, err := engineAndKeyFromPath(u.RequestURI())
	if err != nil {
		return nil, err
	}
	u.Path = ""
	return NewMasterKey(u.String(), enginePath, keyName), nil

}

// NewMasterKey creates a new MasterKey from a Vault address, Transit backend
// path and a key name.
func NewMasterKey(address, enginePath, keyName string) *MasterKey {
	key := &MasterKey{
		VaultAddress: address,
		EnginePath:   enginePath,
		KeyName:      keyName,
		CreationDate: time.Now().UTC(),
	}
	return key
}

// HTTPClient is a wrapper around http.Client used for configuring the
// Vault client.
type HTTPClient struct {
	hc *http.Client
}

// NewHTTPClient creates a new HTTPClient with the provided http.Client.
func NewHTTPClient(hc *http.Client) *HTTPClient {
	return &HTTPClient{hc: hc}
}

// ApplyToMasterKey configures the HTTP client on the provided key.
func (h HTTPClient) ApplyToMasterKey(key *MasterKey) {
	key.httpClient = h.hc
}

// Encrypt takes a SOPS data key, encrypts it with Vault Transit, and stores
// the result in the EncryptedKey field.
//
// Consider using EncryptContext instead.
func (key *MasterKey) Encrypt(dataKey []byte) error {
	return key.EncryptContext(context.Background(), dataKey)
}

// EncryptContext takes a SOPS data key, encrypts it with Vault Transit, and stores
// the result in the EncryptedKey field.
func (key *MasterKey) EncryptContext(ctx context.Context, dataKey []byte) error {
	fullPath := key.encryptPath()

	client, err := vaultClient(key.VaultAddress, key.token, key.httpClient)
	if err != nil {
		log.WithField("Path", fullPath).Info("Encryption failed")
		return err
	}

	secret, err := client.Logical().WriteWithContext(ctx, fullPath, encryptPayload(dataKey))
	if err != nil {
		log.WithField("Path", fullPath).Info("Encryption failed")
		return fmt.Errorf("failed to encrypt sops data key to Vault transit backend '%s': %w", fullPath, err)
	}
	encryptedKey, err := encryptedKeyFromSecret(secret)
	if err != nil {
		log.WithField("Path", fullPath).Info("Encryption failed")
		return fmt.Errorf("failed to encrypt sops data key to Vault transit backend '%s': %w", fullPath, err)
	}

	key.EncryptedKey = encryptedKey
	log.WithField("Path", fullPath).Info("Encryption successful")
	return nil
}

// EncryptIfNeeded encrypts the provided SOPS data key, if it has not been
// encrypted yet.
func (key *MasterKey) EncryptIfNeeded(dataKey []byte) error {
	if key.EncryptedKey == "" {
		return key.Encrypt(dataKey)
	}
	return nil
}

// EncryptedDataKey returns the encrypted data key this master key holds.
func (key *MasterKey) EncryptedDataKey() []byte {
	return []byte(key.EncryptedKey)
}

// SetEncryptedDataKey sets the encrypted data key for this master key.
func (key *MasterKey) SetEncryptedDataKey(enc []byte) {
	key.EncryptedKey = string(enc)
}

// Decrypt decrypts the EncryptedKey field with Vault Transit and returns the result.
//
// Consider using DecryptContext instead.
func (key *MasterKey) Decrypt() ([]byte, error) {
	return key.DecryptContext(context.Background())
}

// DecryptContext decrypts the EncryptedKey field with Vault Transit and returns the result.
func (key *MasterKey) DecryptContext(ctx context.Context) ([]byte, error) {
	fullPath := key.decryptPath()

	client, err := vaultClient(key.VaultAddress, key.token, key.httpClient)
	if err != nil {
		log.WithField("Path", fullPath).Info("Decryption failed")
		return nil, err
	}

	secret, err := client.Logical().WriteWithContext(ctx, fullPath, decryptPayload(key.EncryptedKey))
	if err != nil {
		log.WithField("Path", fullPath).Info("Decryption failed")
		return nil, fmt.Errorf("failed to decrypt sops data key from Vault transit backend '%s': %w", fullPath, err)
	}
	dataKey, err := dataKeyFromSecret(secret)
	if err != nil {
		log.WithField("Path", fullPath).Info("Decryption failed")
		return nil, fmt.Errorf("failed to decrypt sops data key from Vault transit backend '%s': %w", fullPath, err)
	}

	log.WithField("Path", fullPath).Info("Decryption successful")
	return dataKey, nil
}

// NeedsRotation returns whether the data key needs to be rotated or not.
func (key *MasterKey) NeedsRotation() bool {
	// TODO: manage rewrapping https://www.vaultproject.io/api/secret/transit/index.html#rewrap-data
	return time.Since(key.CreationDate) > (vaultTTL)
}

// ToString converts the key to a string representation.
func (key *MasterKey) ToString() string {
	return fmt.Sprintf("%s/v1/%s/keys/%s", key.VaultAddress, key.EnginePath, key.KeyName)
}

// ToMap converts the MasterKey to a map for serialization purposes.
func (key MasterKey) ToMap() map[string]interface{} {
	out := make(map[string]interface{})
	out["vault_address"] = key.VaultAddress
	out["key_name"] = key.KeyName
	out["engine_path"] = key.EnginePath
	out["enc"] = key.EncryptedKey
	out["created_at"] = key.CreationDate.UTC().Format(time.RFC3339)
	return out
}

// TypeToIdentifier returns the string identifier for the MasterKey type.
func (key *MasterKey) TypeToIdentifier() string {
	return KeyTypeIdentifier
}

// encryptPath returns the path for Encrypt requests.
func (key *MasterKey) encryptPath() string {
	return path.Join(key.EnginePath, "encrypt", key.KeyName)
}

// decryptPath returns the path for Decrypt requests.
func (key *MasterKey) decryptPath() string {
	return path.Join(key.EnginePath, "decrypt", key.KeyName)
}

// encryptPayload returns the payload for an encrypt request of the dataKey.
func encryptPayload(dataKey []byte) map[string]interface{} {
	encoded := base64.StdEncoding.EncodeToString(dataKey)
	return map[string]interface{}{
		"plaintext": encoded,
	}
}

// encryptedKeyFromSecret attempts to extract the encrypted key from the data
// of the provided secret.
func encryptedKeyFromSecret(secret *api.Secret) (string, error) {
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("transit backend is empty")
	}
	encrypted, ok := secret.Data["ciphertext"]
	if !ok {
		return "", fmt.Errorf("no encrypted data")
	}
	encryptedKey, ok := encrypted.(string)
	if !ok {
		return "", fmt.Errorf("encrypted ciphertext cannot be cast to string")
	}
	return encryptedKey, nil
}

// decryptPayload returns the payload for a decrypt request of the
// encryptedKey.
func decryptPayload(encryptedKey string) map[string]interface{} {
	return map[string]interface{}{
		"ciphertext": encryptedKey,
	}
}

// dataKeyFromSecret attempts to extract the data key from the data of the
// provided secret.
func dataKeyFromSecret(secret *api.Secret) ([]byte, error) {
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("transit backend is empty")
	}
	decrypted, ok := secret.Data["plaintext"]
	if !ok {
		return nil, fmt.Errorf("no decrypted data")
	}
	plaintext, ok := decrypted.(string)
	if !ok {
		return nil, fmt.Errorf("decrypted plaintext data cannot be cast to string")
	}
	dataKey, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return nil, fmt.Errorf("cannot decode base64 plaintext into data key bytes")
	}
	return dataKey, nil
}

// getCRLFiles returns the list of CRL file paths configured through the
// SopsHCVaultCRLFile environment variable. The value is a comma-separated
// list of paths; surrounding whitespace is trimmed and empty entries are
// treated as a configuration error. When the variable is unset or empty,
// it returns a nil slice, which disables CRL checking.
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
// may contain a PEM-encoded ("X509 CRL") or DER-encoded CRL. Parsing happens
// eagerly, so malformed files or unreadable paths surface as an error at
// client-build time rather than inside the TLS handshake.
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

// newCRLVerifier returns a tls.Config VerifyPeerCertificate callback that
// checks every certificate in the verified chain, except the trust anchor,
// against the provided CRLs. For each such certificate the CRL issued by its
// direct issuer in the chain is consulted.
//
// A CRL is applicable to a certificate only if it is signed by that
// certificate's direct issuer and is currently in effect (ThisUpdate in the
// past, NextUpdate in the future). The policy is hard-fail: the connection is
// rejected if a certificate's serial appears in an applicable CRL, and also if
// any non-anchor certificate has no applicable CRL at all.
//
// The whole chain is walked, so a revoked intermediate CA is caught, not just
// a revoked leaf.
func newCRLVerifier(crls []*x509.RevocationList) func([][]byte, [][]*x509.Certificate) error {
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		// This callback is invoked by crypto/tls only after the default
		// chain verification has run (signatures, validity dates, name and
		// trust-anchor checks), which populates verifiedChains. The CRL
		// check layers revocation on top of that; it does not re-validate
		// certificate validity dates itself. If a caller sets
		// InsecureSkipVerify, no chain is built, verifiedChains is empty and
		// we hard-fail below rather than check revocation against an
		// unverified chain.
		if len(verifiedChains) == 0 || len(verifiedChains[0]) < 2 {
			// Without a verified chain we cannot identify any issuer, and
			// therefore cannot verify a CRL's signature. Under hard-fail
			// this is a rejection.
			return fmt.Errorf("cannot perform CRL check: no verified certificate chain with an issuer")
		}
		chain := verifiedChains[0]
		now := time.Now()

		// Walk every cert/issuer pair in the chain. chain[i] is issued by
		// chain[i+1]; the final element is the trust anchor and has no issuer
		// in the chain, so it is not checked.
		for i := 0; i < len(chain)-1; i++ {
			cert := chain[i]
			issuer := chain[i+1]

			var applicable []*x509.RevocationList
			for _, crl := range crls {
				if err := crl.CheckSignatureFrom(issuer); err != nil {
					continue
				}
				// Reject expired CRLs: a superseded CRL must not be relied
				// upon, otherwise a certificate revoked in a newer CRL could
				// slip through. A zero NextUpdate means the CRL did not
				// specify one, in which case we do not treat it as expired.
				if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
					continue
				}
				// Reject CRLs that are not yet valid: a ThisUpdate in the
				// future means the CRL is not in effect yet and must not be
				// relied upon.
				if now.Before(crl.ThisUpdate) {
					continue
				}
				applicable = append(applicable, crl)
			}
			if len(applicable) == 0 {
				return fmt.Errorf("no valid CRL found for issuer %q of vault server certificate chain (certificate %q)",
					issuer.Subject.CommonName, cert.Subject.CommonName)
			}

			for _, crl := range applicable {
				for _, revoked := range crl.RevokedCertificateEntries {
					if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
						return fmt.Errorf("vault server certificate chain entry %q (serial %s) has been revoked",
							cert.Subject.CommonName, cert.SerialNumber)
					}
				}
			}
		}
		return nil
	}
}

// applyCRLToClient returns an *http.Client, derived from hc (or a sensible
// default when hc is nil), whose TLS configuration performs CRL checking of
// the Vault server's leaf certificate. The caller's client, transport and
// tls.Config are never mutated: they are cloned. Any VerifyPeerCertificate
// already set by the caller is preserved and runs before the CRL check.
//
// If hc carries a transport that is not an *http.Transport, it cannot be
// introspected and an error is returned (hard-fail).
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

// configureCRL applies CRL checking to the Vault client configuration based on
// the SopsHCVaultCRLFile environment variable. It returns the *http.Client to
// use, unchanged when the variable is unset. A non-https:// Vault address is an
// error, since there is no TLS handshake in which to check revocation.
//
// hc is the caller-injected client (may be nil); base is the client the Vault
// API configured from its own environment (VAULT_CACERT, VAULT_CLIENT_CERT,
// ...). The verifier is layered onto hc when injected, otherwise onto base, so
// Vault's env-derived TLS settings are kept rather than discarded.
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

	// When the caller injected a client, layer CRL checking onto it.
	// Otherwise layer it onto the client the Vault API configured from the
	// environment, so VAULT_CACERT / VAULT_CLIENT_CERT and friends are not
	// lost when CRL checking is enabled.
	target := hc
	if target == nil {
		target = base
	}

	return applyCRLToClient(target, crls)
}

// vaultClient returns a new Vault client, configured with the given address
// and token.
func vaultClient(address, token string, hc *http.Client) (*api.Client, error) {
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, fmt.Errorf("cannot create default Vault config: %w", cfg.Error)
	}
	cfg.Address = address

	allowlist, err := getAllowlist()
	if err != nil {
		return nil, err
	}
	if !allowlist.Allows(address) {
		return nil, fmt.Errorf("Allowlist does not allow %s", address)
	}

	// cfg.HttpClient is the client the Vault API has configured from its own
	// environment (VAULT_CACERT, VAULT_CLIENT_CERT, ...). It is used as the
	// base for CRL checking when the caller did not inject a client, so those
	// TLS settings are preserved.
	hc, err = configureCRL(address, hc, cfg.HttpClient)
	if err != nil {
		return nil, err
	}
	if hc != nil {
		cfg.HttpClient = hc
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("cannot create Vault client: %w", err)
	}

	if token != "" {
		client.SetToken(token)
	}
	// Provided token takes precedence over the user's token.
	if client.Token() == "" {
		if token, err = userVaultToken(); err != nil {
			return nil, fmt.Errorf("cannot get Vault token: %w", err)
		}
		if token != "" {
			client.SetToken(token)
		}
	}

	return client, nil
}

// userVaultToken returns the token from `$HOME/.vault-token` if the file
// exists. It returns an error if the file exists but cannot be read from.
// If the file does not exist, it returns an empty string.
func userVaultToken() (string, error) {
	homePath, err := homedir.Dir()
	if err != nil {
		return "", fmt.Errorf("error getting user's home directory: %w", err)
	}
	tokenPath := filepath.Join(homePath, defaultTokenFile)

	f, err := os.Open(tokenPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

// engineAndKeyFromPath returns the engine path and key name from the full
// path, or an error.
func engineAndKeyFromPath(fullPath string) (enginePath, keyName string, err error) {
	// Running vault behind a reverse proxy with longer URLs seems not to be
	// supported by the Vault client API. Check for this here.
	// TODO(hidde): this may no longer be necessary with newer Vault versions,
	//  but needs to be confirmed.
	if re := regexp.MustCompile(`/[^/]+/v[\d]+/[^/]+/[^/]+/[^/]+`); re.Match([]byte(fullPath)) {
		err = fmt.Errorf("running Vault with a prefixed URL is not supported! (Format has to be like " +
			"https://vault.example.com:8200/v1/transit/keys/keyName)")
		return
	} else if re := regexp.MustCompile(`/v[\d]+/[^/]+/[^/]+/[^/]+`); !re.Match([]byte(fullPath)) {
		err = fmt.Errorf("vault path does not seem to be formatted correctly: (eg. " +
			"https://vault.example.com:8200/v1/transit/keys/keyName)")
		return
	}

	fullPath = strings.Trim(fullPath, "/")
	dirs := strings.Split(fullPath, "/")

	keyName = dirs[len(dirs)-1]
	enginePath = path.Join(dirs[1 : len(dirs)-2]...)
	return
}
