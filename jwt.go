// Wrapper over jose utilities that implements JSON Web Signature (JWS) and JSON Web Encryption (JWE).

package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	prvKeyBits         = 2048
	signatureAlgorithm = jose.RS512
	keyAlgorithm       = jose.RSA_OAEP
	contentAlgorithm   = jose.A128GCM
)

func genKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, prvKeyBits)
}

// Claims specify registered claim names specified in https://tools.ietf.org/html/rfc7519#section-4.1.
type Claims struct {
	Issuer    string      `json:"iss,omitempty"`
	Subject   string      `json:"sub,omitempty"`
	Audience  []string    `json:"aud,omitempty"`
	Expiry    NumericDate `json:"exp,omitempty"`
	NotBefore NumericDate `json:"nbf,omitempty"`
	IssuedAt  NumericDate `json:"iat,omitempty"`
	ID        string      `json:"jti,omitempty"`

	timeNow func() time.Time
}

// ValidateWithLeeway checks claims in a token against expected values. A custom leeway may be specified for comparing
// time values. You may pass a zero value to check time values with no leeway, but you should note that numeric date
// values are rounded to the nearest second and sub-second precision is not supported.
func (c Claims) ValidateWithLeeway(e Claims, leeway time.Duration) error {
	if e.Issuer != "" && e.Issuer != c.Issuer {
		return fmt.Errorf("Invalid issuer. Expected: %q, got: %q", e.Issuer, c.Issuer)
	}

	if e.Subject != "" && e.Subject != c.Subject {
		return fmt.Errorf("Invalid subject. Expected: %q, got: %q", e.Subject, c.Subject)
	}

	if e.ID != "" && e.ID != c.ID {
		return fmt.Errorf("Invalid ID. Expected: %q, got: %q", e.ID, c.ID)
	}

	if len(e.Audience) != 0 {
		if len(e.Audience) != len(c.Audience) {
			return fmt.Errorf("Invalid Audience. Expected len: %d, got: %d", len(e.Audience), len(c.Audience))
		}

		audienceLookup := map[string]struct{}{}
		for _, v := range c.Audience {
			audienceLookup[v] = struct{}{}
		}

		for _, v := range e.Audience {
			if _, ok := audienceLookup[v]; !ok {
				return fmt.Errorf("Invalid Audience. Expected: %q and  not found.", v)
			}
		}
	}

	if c.timeNow == nil {
		c.timeNow = time.Now
	}

	now := c.timeNow()
	if now.IsZero() {
		return nil
	}

	if now.Add(leeway).Before(c.NotBefore.Time()) {
		return fmt.Errorf("Violated NotBefore. It is before specified time %q", c.NotBefore.Time().String())
	}

	if now.Add(-leeway).After(c.Expiry.Time()) {
		return fmt.Errorf("Exipred claim. Expiration time %q", c.Expiry.Time())

	}

	return nil
}

// jwtPayload defines special claim custom payload.
// Needed to avoid collisions. https://tools.ietf.org/html/rfc7519#section-4.2
type jwtPayload struct {
	Payload interface{} `json:"payload"`
}

// Builder is an builder that is able to construct nested JWT or JWS with custom payload claim or other claims.
// Nested JSON Web Token is token that is signed and encrypted respectively).
type Builder struct {
	*SignedObtainer

	// Private key encryption and signatures used with every JWT handled by this builder.
	prvKey *rsa.PrivateKey

	signer    jose.Signer
	encrypter jose.Encrypter
}

func NewBuilder() (*Builder, error) {
	prvKey, err := genKey()
	if err != nil {
		return nil, fmt.Errorf("JWT Builder: Could not generate RSA key. Err: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: signatureAlgorithm,
			Key:       prvKey,
		},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("JWT Builder: Could not build signer. Err: %v", err)
	}

	encrypter, err := jose.NewEncrypter(
		contentAlgorithm,
		jose.Recipient{
			Algorithm: keyAlgorithm,
			Key:       &prvKey.PublicKey,
		},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"),
	)
	if err != nil {
		return nil, fmt.Errorf("JWT Builder: Could not build encrypter. Err: %v", err)
	}

	return &Builder{
		SignedObtainer: NewSignedObtainer(&prvKey.PublicKey),
		prvKey:         prvKey,
		signer:         signer,
		encrypter:      encrypter,
	}, nil
}

// SignedAndEncryptedJWT constructs nested JSON Web Token that is both signed and encrypted respectively
func (j *Builder) SignedAndEncryptedJWT() *BuilderWrapper {
	return &BuilderWrapper{engine: jwt.SignedAndEncrypted(j.signer, j.encrypter)}
}

// JWS constructs JSON Web Token that is only signed.
func (j *Builder) JWS() *BuilderWrapper {
	return &BuilderWrapper{engine: jwt.Signed(j.signer)}
}

// JWE constructs JSON Web Token that is only encrypted.
func (j *Builder) JWE() *BuilderWrapper {
	return &BuilderWrapper{engine: jwt.Encrypted(j.encrypter)}
}

// FromSignedAndEncryptedJWT parsed given token as nested JSON Web Token's and decrypts it.
// Returned ObtainerWrapper can be used to fetch claims. Signature verification is done by ObtainerWrapper.
func (j *Builder) FromSignedAndEncryptedJWT(token string) *ObtainerWrapper {
	nestedJWT, err := jwt.ParseSignedAndEncrypted(token)
	if err != nil {
		return &ObtainerWrapper{err: fmt.Errorf("JWT Builder: Could not parse given token as nested JSON Web Token. Err: %v", err)}
	}

	signedJWT, err := nestedJWT.Decrypt(j.prvKey)
	if err != nil {
		return &ObtainerWrapper{err: fmt.Errorf("JWT Builder: Could not decrypt given nested JSON Web Token. Err: %v", err)}
	}

	return &ObtainerWrapper{parsedToken: signedJWT, key: &j.prvKey.PublicKey}
}

// FromJWS decrypts JSON Web Token's.
// Returned ObtainerWrapper can be used to fetch claims. Decryption is done by ObtainerWrapper.
func (j *Builder) FromJWE(token string) *ObtainerWrapper {
	encrypted, err := jwt.ParseEncrypted(token)
	if err != nil {
		return &ObtainerWrapper{err: fmt.Errorf("JWT Builder: Could not parse given token as encrypted JSON Web Token. Err: %v", err)}
	}

	return &ObtainerWrapper{parsedToken: encrypted, key: j.prvKey}
}

type SignedObtainer struct {
	pubKey *rsa.PublicKey

	timeNow func() time.Time
}

func NewSignedObtainer(publicKey *rsa.PublicKey) *SignedObtainer {
	return &SignedObtainer{
		pubKey:  publicKey,
		timeNow: time.Now,
	}
}

func (j *SignedObtainer) PublicRSAKey() rsa.PublicKey {
	return *j.pubKey
}

func (j *SignedObtainer) PublicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key: j.pubKey,
	}
}


// FromJWS parses given JWS.
// Returned ObtainerWrapper can be used to fetch claims. Signature verification is done by ObtainerWrapper.
func (j *SignedObtainer) FromJWS(token string) *ObtainerWrapper {
	signed, err := jwt.ParseSigned(token)
	if err != nil {
		return &ObtainerWrapper{err: fmt.Errorf("JWT Builder: Could not parse given token as signed JSON Web Token. Err: %v", err)}
	}

	return &ObtainerWrapper{parsedToken: signed, key: j.pubKey}
}

// VerifyClaims verifies standard "iss", "sub", "aud", "exp" claims from JWT RFC (https://tools.ietf.org/html/rfc7519).
func (j *SignedObtainer) VerifyStdClaims(claims Claims, expected Claims) error {
	err := claims.ValidateWithLeeway(expected, 1*time.Second)
	if err != nil {
		return fmt.Errorf("JWT Builder: claims validation failed. Err: %v", err)
	}
	return nil
}

// BuilderWrapper wraps specified engine and enabling packing and serializing claims into single token.
type BuilderWrapper struct {
	engine interface{}
}

// Claims encodes claims into JWE/JWS form. Multiple calls will merge claims
// into single JSON object.
func (b *BuilderWrapper) Claims(claims interface{}) *BuilderWrapper {
	switch builder := b.engine.(type) {
	case jwt.Builder:
		b.engine = builder.Claims(claims)
	case jwt.NestedBuilder:
		b.engine = builder.Claims(claims)
	}
	return b
}

// Payload encodes payload into JWE/JWS form in a `payload` field. Multiple calls will override payload.
func (b *BuilderWrapper) Payload(payload interface{}) *BuilderWrapper {
	switch builder := b.engine.(type) {
	case jwt.Builder:
		b.engine = builder.Claims(
			jwtPayload{
				Payload: payload,
			},
		)
	case jwt.NestedBuilder:
		b.engine = builder.Claims(
			jwtPayload{
				Payload: payload,
			},
		)
	}
	return b
}

func (b *BuilderWrapper) CompactSerialize() (string, error) {
	switch builder := b.engine.(type) {
	case jwt.Builder:
		return builder.CompactSerialize()
	case jwt.NestedBuilder:
		return builder.CompactSerialize()
	}
	return "", errors.New("JWT BuildWrapper internal error: Wrong type of wrapped engine.")
}

// ObtainerWrapper wraps token and enables deserialization from token.
type ObtainerWrapper struct {
	err         error
	parsedToken *jwt.JSONWebToken
	key         interface{} // *rsa.PublicKey or rsa.PrivateKey
}

func (o *ObtainerWrapper) Claims(out interface{}) error {
	if o.err != nil {
		return o.err
	}
	err := o.parsedToken.Claims(o.key, &out)
	if err != nil {
		return fmt.Errorf("JWT ObtainerWrapper: Could not deserialize JSON Web Token into given type. Err: %v", err)
	}
	return nil
}

func (o *ObtainerWrapper) Payload(out interface{}) error {
	if o.err != nil {
		return o.err
	}
	payload := jwtPayload{
		Payload: out,
	}
	err := o.parsedToken.Claims(o.key, &payload)
	if err != nil {
		return fmt.Errorf("JWT ObtainerWrapper: Could not deserialize JSON Web Token into given payload type. Err: %v", err)
	}
	return nil
}

func (o *ObtainerWrapper) StdClaims() (Claims, error) {
	if o.err != nil {
		return Claims{}, o.err
	}
	var claims Claims
	err := o.parsedToken.Claims(o.key, &claims)
	if err != nil {
		return Claims{}, fmt.Errorf("JWT ObtainerWrapper: Could not deserialize JSON Web Token into standard claims. Err: %v", err)
	}
	return claims, nil
}

// NumericDate represents date and time as the number of seconds since the
// epoch, including leap seconds. Non-integer values can be represented
// in the serialized format, but we round to the nearest second.
type NumericDate int64

// NewNumericDate constructs NumericDate from time.Time value.
func NewNumericDate(t time.Time) NumericDate {
	if t.IsZero() {
		return NumericDate(0)
	}

	// While RFC 7519 technically states that NumericDate values may be
	// non-integer values, we don't bother serializing timestamps in
	// claims with sub-second accuracy and just round to the nearest
	// second instead.
	return NumericDate(t.Unix())
}

// MarshalJSON serializes the given NumericDate into its JSON representation.
func (n NumericDate) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(int64(n), 10)), nil
}

// UnmarshalJSON reads a date from its JSON representation.
func (n *NumericDate) UnmarshalJSON(b []byte) error {
	s := string(b)

	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("Failed to unmarshall NumericDate. Err: %v", err)
	}

	*n = NumericDate(f)
	return nil
}

// Time returns time.Time representation of NumericDate.
func (n NumericDate) Time() time.Time {
	return time.Unix(int64(n), 0)
}
