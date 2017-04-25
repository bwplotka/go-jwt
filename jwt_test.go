package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stdClaims() Claims {
	now := time.Now()
	return Claims{
		Issuer:   "me",
		Audience: []string{"some_aud", "some_aud2"},
		Expiry:   NewNumericDate(now.Add(20 * time.Minute)),
		IssuedAt: NewNumericDate(now),
		ID:       "id",
		Subject:  "sub",
	}
}

type TestPayload struct {
	SomeSlice        []string `json:"slice"`
	SomeString       string   `json:"string"`
	SomeInt          int      `json:"int"`
	SomeNestedStruct Claims   `json:"nested"`
}

func payload() TestPayload {
	return TestPayload{
		SomeSlice: []string{
			"openid",
			"email",
			"groups",
			"profile",
			"offline_access",
		},
		SomeString:       "sdfsf",
		SomeInt:          1243,
		SomeNestedStruct: stdClaims(),
	}
}

func TestBuilder_ExampleSerializeObtain_OK(t *testing.T) {
	p := "some_payload"
	cl := stdClaims()

	b, err := NewDefaultBuilder()
	require.NoError(t, err)

	token, err := b.SignedAndEncryptedJWT().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	obtainer := b.FromSignedAndEncryptedJWT(token)

	// Test payload.
	var fetched string
	err = obtainer.Payload(&fetched)
	require.NoError(t, err)

	assert.EqualValues(t, p, fetched)

	// Test std claims from StdClaims() method.
	fetchedStdClaims, err := obtainer.StdClaims()
	require.NoError(t, err)

	err = b.VerifyStdClaims(fetchedStdClaims, cl)
	assert.NoError(t, err)
}

func TestBuilder_NestedJWTSerializeObtain_OK(t *testing.T) {
	p := payload()
	cl := stdClaims()

	b, err := NewDefaultBuilder()
	require.NoError(t, err)

	token, err := b.SignedAndEncryptedJWT().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	obtainer := b.FromSignedAndEncryptedJWT(token)

	// Test payload.
	fetched := TestPayload{}
	err = obtainer.Payload(&fetched)
	require.NoError(t, err)

	assert.EqualValues(t, p, fetched)

	// Test std claims from Claims() method.
	var fetchedCl Claims
	err = obtainer.Claims(&fetchedCl)
	require.NoError(t, err)

	err = b.VerifyStdClaims(fetchedCl, cl)
	assert.NoError(t, err)

	// Test std claims from StdClaims() method.
	fetchedStdClaims, err := obtainer.StdClaims()
	require.NoError(t, err)

	err = b.VerifyStdClaims(fetchedStdClaims, cl)
	assert.NoError(t, err)
}

func TestBuilder_NestedJWTSerializeObtain_DifferentKeys(t *testing.T) {
	p := payload()
	cl := stdClaims()

	b, err := NewDefaultBuilder()
	require.NoError(t, err)

	token, err := b.SignedAndEncryptedJWT().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	yetAnotherBuilder, err := NewDefaultBuilder()
	require.NoError(t, err)

	fetched := TestPayload{}
	obtainer := yetAnotherBuilder.FromSignedAndEncryptedJWT(token)

	// Test payload.
	err = obtainer.Payload(&fetched)
	require.Error(t, err, "Different builder is used, so keys are different")
}

func TestBuilder_JWESerializeObtain_OK(t *testing.T) {
	p := payload()
	cl := stdClaims()

	b, err := NewDefaultBuilder()
	require.NoError(t, err)

	token, err := b.JWE().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	obtainer := b.FromJWE(token)

	// Test payload.
	fetched := TestPayload{}
	err = obtainer.Payload(&fetched)
	require.NoError(t, err)

	assert.EqualValues(t, p, fetched)

	// Test std claims from Claims() method.
	var fetchedCl Claims
	err = obtainer.Claims(&fetchedCl)
	require.NoError(t, err)

	err = b.VerifyStdClaims(fetchedCl, cl)
	assert.NoError(t, err)

	// Test std claims from StdClaims() method.
	fetchedStdClaims, err := obtainer.StdClaims()
	require.NoError(t, err)

	err = b.VerifyStdClaims(fetchedStdClaims, cl)
	assert.NoError(t, err)
}

func TestBuilder_JWESerializeObtain_DifferentKeys(t *testing.T) {
	p := payload()
	cl := stdClaims()

	b, err := NewDefaultBuilder()
	require.NoError(t, err)

	token, err := b.JWE().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	yetAnotherBuilder, err := NewDefaultBuilder()
	require.NoError(t, err)

	fetched := TestPayload{}
	obtainer := yetAnotherBuilder.FromJWE(token)

	// Test payload.
	err = obtainer.Payload(&fetched)
	require.Error(t, err, "Different builder is used, so keys are different")
}

func TestBuilder_JWSSerializeObtain_OK(t *testing.T) {
	p := payload()
	cl := stdClaims()

	b, err := NewDefaultBuilder()
	require.NoError(t, err)

	token, err := b.JWS().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	signedObtainer := NewSignedObtainer(
		newPubJWK(
			&b.prvKey.PublicKey,
			string(defaultSignatureAlgorithm),
			signatureJWKUse,
		),
	)

	obtainer := signedObtainer.FromJWS(token)

	// Test payload.
	fetched := TestPayload{}
	err = obtainer.Payload(&fetched)
	require.NoError(t, err)

	assert.EqualValues(t, p, fetched)

	// Test std claims from Claims() method.
	var fetchedCl Claims
	err = obtainer.Claims(&fetchedCl)
	require.NoError(t, err)

	err = signedObtainer.VerifyStdClaims(fetchedCl, cl)
	assert.NoError(t, err)

	// Test std claims from StdClaims() method.
	fetchedStdClaims, err := obtainer.StdClaims()
	require.NoError(t, err)

	err = signedObtainer.VerifyStdClaims(fetchedStdClaims, cl)
	assert.NoError(t, err)
}

func TestBuilder_JWSSerializeObtain_DifferentKeys(t *testing.T) {
	p := payload()
	cl := stdClaims()

	b, err := NewDefaultBuilder()
	require.NoError(t, err)

	token, err := b.JWS().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	yetAnotherBuilder, err := NewDefaultBuilder()
	require.NoError(t, err)

	signedObtainer := NewSignedObtainer(
		newPubJWK(
			&yetAnotherBuilder.prvKey.PublicKey,
			string(defaultSignatureAlgorithm),
			signatureJWKUse,
		),
	)

	fetched := TestPayload{}
	obtainer := signedObtainer.FromJWS(token)

	// Test payload.
	err = obtainer.Payload(&fetched)
	require.Error(t, err, "Different builder is used, so keys are different")
}

func TestSignedObtainer_ValidJWK(t *testing.T) {
	b, err := NewDefaultBuilder()
	require.NoError(t, err)

	jwk := b.PublicJWK()
	assert.Equal(t, jwk.Algorithm, string(defaultSignatureAlgorithm))
	assert.Equal(t, jwk.Use, signatureJWKUse)
	assert.True(t, jwk.KeyID != "")

	signedObtainer := NewSignedObtainer(
		newPubJWK(
			&b.prvKey.PublicKey,
			string(defaultSignatureAlgorithm),
			signatureJWKUse,
		),
	)
	jwkFromObtainer := signedObtainer.PublicJWK()

	assert.EqualValues(t, jwk, jwkFromObtainer)
}

func parseHeader(token string) (map[string]string, error) {
	t := strings.Split(token, ".")
	if len(t) < 3 {
		return nil, fmt.Errorf("String %q does not have 3 components.", token)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(t[0])
	if err != nil {
		return nil, err
	}

	header := map[string]string{}
	err = json.Unmarshal(decoded, &header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func TestBuilder_JWS_ValidHeaders(t *testing.T) {
	p := payload()
	cl := stdClaims()

	b, err := NewDefaultBuilder()
	require.NoError(t, err)

	token, err := b.JWS().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	header, err := parseHeader(token)
	require.NoError(t, err)

	assert.Len(t, header, 2)
	assert.Equal(t, string(defaultSignatureAlgorithm), header["alg"])
	assert.True(t, header["kid"] != "")
}

func TestBuilder_JWE_ValidHeaders(t *testing.T) {
	p := payload()
	cl := stdClaims()

	b, err := NewDefaultBuilder()
	require.NoError(t, err)

	token, err := b.JWE().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	header, err := parseHeader(token)
	require.NoError(t, err)

	assert.Len(t, header, 5)
	assert.Equal(t, "JWT", header["cty"])
	assert.Equal(t, "JWT", header["typ"])
	assert.Equal(t, string(defaultKeyAlgorithm), header["alg"])
	assert.Equal(t, string(defaultContentAlgorithm), header["enc"])
	assert.True(t, header["kid"] != "")
}
