// Wrapper over jose utilities that implements JSON Web Signature (JWS) and JSON Web Encryption (JWE).

package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	prvKeyBits         = 2048
	signatureAlgorithm = jose.PS512
	keyAlgorithm       = jose.RSA_OAEP
	contentAlgorithm   = jose.A128GCM
)

func genKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, prvKeyBits)
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
func (j *SignedObtainer) VerifyStdClaims(claims jwt.Claims, expected jwt.Claims) error {
	err := claims.ValidateWithLeeway(jwt.Expected{
		Subject:  expected.Subject,
		ID:       expected.ID,
		Audience: expected.Audience,
		Issuer:   expected.Issuer,
		Time:     j.timeNow(),
	}, 1*time.Second)
	if err != nil {
		return fmt.Errorf("JWT Builder: claims validation failed. Err: %v", err)
	}
	return nil
}

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
		b.engine =  builder.Claims(claims)
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

func (o *ObtainerWrapper) StdClaims() (jwt.Claims, error) {
	if o.err != nil {
		return jwt.Claims{}, o.err
	}
	var claims jwt.Claims
	err := o.parsedToken.Claims(o.key, &claims)
	if err != nil {
		return jwt.Claims{}, fmt.Errorf("JWT ObtainerWrapper: Could not deserialize JSON Web Token into standard claims. Err: %v", err)
	}
	return claims, nil
}
