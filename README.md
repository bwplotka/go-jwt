# go-jwt

Golang JSON Web Token builder with easy to use API for JWS and nested JWT (JWS+JWE)


## Usage:

```go
	p := "some_payload"
	cl := jwt.Claims{
	    // You standard claims here...
	}

	b, err := NewBuilder()
	if err != nil {
	    // Handle error here..
	}

	token, err := b.SignedAndEncryptedJWT().
		Claims(cl).
		Payload(p).
		CompactSerialize()
	if err != nil {
        // Handle error here..
    }
    
    // Generated valid nested JWT in token variable!
    
	obtainer := b.FromSignedAndEncryptedJWT(token)

	var fetched string
	err = obtainer.Payload(&fetched)
	if err != nil {
        // Handle error here..
    }

	// fetched == "some_payload" again!

	fetchedStdClaims, err := obtainer.StdClaims()
	if err != nil {
        // Handle error here..
    }
   
    // Have our standard claims again in fetchedStdClaims variable.
    
```