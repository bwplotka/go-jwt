package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2/jwt"
)

func stdClaims() Claims {
	now := time.Now()
	return Claims{
		Issuer:   "me",
		Audience: []string{"some_aud", "some_aud2"},
		Expiry:   jwt.NewNumericDate(now.Add(20 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(now),
		ID:       "id",
		Subject:  "sub",
	}
}

type TestPayload struct {
	SomeSlice        []string   `json:"slice"`
	SomeString       string     `json:"string"`
	SomeInt          int        `json:"int"`
	SomeNestedStruct Claims `json:"nested"`
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

	b, err := NewBuilder()
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

	b, err := NewBuilder()
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

	b, err := NewBuilder()
	require.NoError(t, err)

	token, err := b.SignedAndEncryptedJWT().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	yetAnotherBuilder, err := NewBuilder()
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

	b, err := NewBuilder()
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

	b, err := NewBuilder()
	require.NoError(t, err)

	token, err := b.JWE().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	yetAnotherBuilder, err := NewBuilder()
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

	b, err := NewBuilder()
	require.NoError(t, err)

	token, err := b.JWS().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	signedObtainer := NewSignedObtainer(&b.prvKey.PublicKey)

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

	b, err := NewBuilder()
	require.NoError(t, err)

	token, err := b.JWS().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	require.NoError(t, err)

	yetAnotherBuilder, err := NewBuilder()
	require.NoError(t, err)

	signedObtainer := NewSignedObtainer(&yetAnotherBuilder.prvKey.PublicKey)

	fetched := TestPayload{}
	obtainer := signedObtainer.FromJWS(token)

	// Test payload.
	err = obtainer.Payload(&fetched)
	require.Error(t, err, "Different builder is used, so keys are different")
}
