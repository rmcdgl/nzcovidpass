package nzcovidpass

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/veraison/go-cose"
)

const officialKeys string = `{
	"keys": [ 
		{
			"kid": "z12Kf7UQ",
			"kty": "EC",
			"crv":"P-256",
			 "x":"DQCKJusqMsT0u7CjpmhjVGkHln3A3fS-ayeH4Nu52tc",
			 "y":"lxgWzsLtVI8fqZmTPPo9nZ-kzGs7w7XO8-rUU68OxmI"
		}
	]
}
`

const testKeys string = `{
	"keys": [ 
		{
			"kid": "key-1",
			"kty": "EC",
			"crv":"P-256",
			 "x":"zRR-XGsCp12Vvbgui4DD6O6cqmhfPuXMhi1OxPl8760",
			 "y":"Iv5SU6FuW-TRYh5_GOrJlcV_gpF_GpFQhCOD8LSk3T0"
		}
	]
}`

// Decoded is a NZ COVID Pass
type Decoded struct {
	Vc         verifiedCredential
	NotBefore  time.Time
	Expiration time.Time
}

func unprefix(prefixObject string) (string, error) {
	if !strings.HasPrefix(prefixObject, "NZCP:/1/") {
		return "", errors.New("data does not start with NZCP:/1/ prefix")
	}

	return strings.TrimPrefix(prefixObject, "NZCP:/1/"), nil
}

type coseHeader struct {
	// Cryptographic algorithm. See COSE Algorithms Registry:
	// https://www.iana.org/assignments/cose/cose.xhtml
	Alg int `cbor:"1,keyasint,omitempty"`
	// Key identifier
	Kid []byte `cbor:"4,keyasint,omitempty"`
}

type signedCWT struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[interface{}]interface{} // NZ COVID Pass doesn't use this
	Payload     []byte
	Signature   []byte
}

type unverifiedCOSE struct {
	v      signedCWT
	p      coseHeader
	claims claims
}

// PublicKeyProvider is typically implemented using a JSON Web Key Set, or by
// pinning a specific government certificate.
type PublicKeyProvider interface {
	// GetPublicKey returns the public key of the certificate for the specified
	// key identifier (or country), or an error if the public key was not found.
	//
	// Country is a ISO 3166 alpha-2 code, e.g. CH.
	//
	// kid are the first 8 bytes of the SHA256 digest of the certificate in DER
	// encoding.
	GetPublicKey(kid []byte) (crypto.PublicKey, error)
}

type pubkeyOnlyCertificateProvider struct {
	pubKeys map[string]crypto.PublicKey
}

func (prov pubkeyOnlyCertificateProvider) GetPublicKey(kid []byte) (crypto.PublicKey, error) {
	key := prov.pubKeys[string(kid)]
	if key != nil {
		return key, nil
	}

	return nil, fmt.Errorf("no key with kid: %s", kid)
}

func NewNZCertificateProvider() (PublicKeyProvider, error) {

	set, err := jwk.ParseString(officialKeys)

	if err != nil {
		return nil, err
	}

	keys := make(map[string]crypto.PublicKey)

	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawkey ecdsa.PublicKey
		if err := key.Raw(&rawkey); err != nil {
			return nil, err
		}

		keys[key.KeyID()] = &rawkey
	}

	return &pubkeyOnlyCertificateProvider{pubKeys: keys}, nil
}

func NewNZTestCertificateProvider() (PublicKeyProvider, error) {
	c, err := NewNZCertificateProvider()
	if err != nil {
		return nil, err
	}

	set, err := jwk.ParseString(testKeys)

	if err != nil {
		return nil, err
	}

	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawkey ecdsa.PublicKey
		if err := key.Raw(&rawkey); err != nil {
			return nil, err
		}

		c.(*pubkeyOnlyCertificateProvider).pubKeys[key.KeyID()] = &rawkey
	}

	return c, nil
}

func (u *unverifiedCOSE) verify(expired func(time.Time) bool, certprov PublicKeyProvider) error {
	kid := u.p.Kid // protected header

	alg := u.p.Alg // protected header

	key, err := certprov.GetPublicKey(kid)
	if err != nil {
		return err
	}

	verifier := &cose.Verifier{
		PublicKey: key,
	}

	// COSE algorithm parameter ES256
	// https://datatracker.ietf.org/doc/draft-ietf-cose-rfc8152bis-algs/12/
	if alg == -37 {
		verifier.Alg = cose.PS256
	} else if alg == -7 {
		verifier.Alg = cose.ES256
	} else {
		return fmt.Errorf("unknown alg: %d", alg)
	}

	// Following note kept from https://github.com/stapelberg/coronaqr

	// We need to use custom verification code instead of the existing Go COSE
	// packages:
	//
	// - go.mozilla.org/cose lacks sign1 support
	//
	// - github.com/veraison/go-cose is a fork which adds sign1 support, but
	//   re-encodes protected headers during signature verification, which does
	//   not pass e.g. dgc-testdata/common/2DCode/raw/CO1.json
	toBeSigned, err := sigStructure(u.v.Protected, u.v.Payload)
	if err != nil {
		return err
	}

	digest, err := hashSigStructure(toBeSigned, verifier.Alg.HashFunc)
	if err != nil {
		return err
	}

	if err := verifier.Verify(digest, u.v.Signature); err != nil {
		return err
	}

	expiration := time.Unix(u.claims.Exp, 0)
	if expired(expiration) {
		return fmt.Errorf("certificate expired at %v", expiration)
	}

	validFrom := time.Unix(u.claims.Nbf, 0)
	if validFrom.After(time.Now()) {
		return fmt.Errorf("certificate isn't valid until %v", validFrom)
	}

	return nil
}

func (u *unverifiedCOSE) decoded() *Decoded {
	vc := u.claims.Vc
	return &Decoded{
		Vc:         vc,
		NotBefore:  time.Unix(u.claims.Nbf, 0),
		Expiration: time.Unix(u.claims.Exp, 0),
	}
}

type claims struct {
	Iss string             `cbor:"1,keyasint"`
	Exp int64              `cbor:"4,keyasint"`
	Nbf int64              `cbor:"5,keyasint"`
	Cti []byte             `cbor:"7,keyasint"`
	Vc  verifiedCredential `cbor:"vc"`
}

type verifiedCredential struct {
	Ctx      []string          `cbor:"@context"`
	Version  string            `cbor:"version"`
	Type     []string          `cbor:"type"`
	Csubject credentialSubject `cbor:"credentialSubject"`
}

type credentialSubject struct {
	GivenName  string `cbor:"givenName"`
	FamilyName string `cbor:"familyName"`
	Dob        string `cbor:"dob"`
}

func decodeCOSE(coseData []byte) (*unverifiedCOSE, error) {
	var v signedCWT
	if err := cbor.Unmarshal(coseData, &v); err != nil {
		return nil, fmt.Errorf("cbor.Unmarshal: %v", err)
	}

	var p coseHeader
	if len(v.Protected) > 0 {
		if err := cbor.Unmarshal(v.Protected, &p); err != nil {
			return nil, fmt.Errorf("cbor.Unmarshal(v.Protected): %v", err)
		}
	}

	var c claims
	if err := cbor.Unmarshal(v.Payload, &c); err != nil {
		return nil, fmt.Errorf("cbor.Unmarshal(v.Payload): %v", err)
	}

	return &unverifiedCOSE{
		v:      v,
		p:      p,
		claims: c,
	}, nil
}

// Unverified is a NZ COVID Pass that has been decoded but not verified
type Unverified struct {
	u       *unverifiedCOSE
	decoder *Decoder
}

// Verify checks the cryptographic signature and returns the verified data
func (u *Unverified) Verify(certprov PublicKeyProvider) (*Decoded, error) {
	expired := u.decoder.Expired
	if expired == nil {
		expired = func(expiration time.Time) bool {
			return time.Now().After(expiration)
		}
	}
	if err := u.u.verify(expired, certprov); err != nil {
		return nil, err
	}

	return u.u.decoded(), nil
}

// Decoder is a NZ COVID Pass decoder.
type Decoder struct {
	Expired func(time.Time) bool
}

// Decode decodes the NZ COVID Pass QR Code data
func (d *Decoder) Decode(qrdata string) (*Unverified, error) {
	unprefixed, err := unprefix(qrdata)
	if err != nil {
		return nil, err
	}

	coseData, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(unprefixed)
	if err != nil {
		return nil, err
	}

	unverified, err := decodeCOSE(coseData)
	if err != nil {
		return nil, err
	}

	return &Unverified{
		decoder: d,
		u:       unverified,
	}, nil
}

// DefaultDecoder is a ready-to-use Decoder.
var DefaultDecoder = &Decoder{}

// Decode decodes the specified EU Digital COVID Certificate (EUDCC) QR code
// data.
func Decode(qrdata string) (*Unverified, error) {
	return DefaultDecoder.Decode(qrdata)
}

func DecodeAndVerify(qrdata string, certprov PublicKeyProvider) (*Decoded, error) {
	unverified, err := Decode(qrdata)
	if err != nil {
		return nil, err
	}
	return unverified.Verify(certprov)
}
