# go-jwt

Golang JSON Web Token builder with easy to use API for JWS and nested JWT (JWS+JWE)

It wraps and is inspired by gopkg.in/square/go-jose.v2 (especially `jwt` subpackage)
## Usage:

```go
package main

import "github.com/Bplotka/go-jwt"

func main() {
    p := "some_payload"
    cl := jwt.Claims{
        // Your standard claims here...
    }
    
    b, err := jwt.NewBuilder()
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
    
    // Generated valid nested JWT in `token` variable!
    
    obtainer := b.FromSignedAndEncryptedJWT(token)
    
    var fetched string
    err = obtainer.Payload(&fetched)
    if err != nil {
        // Handle error here..
    }
    
    // We have "some_payload" again in `fetched` variable.
    
    fetchedStdClaims, err := obtainer.StdClaims()
    if err != nil {
        // Handle error here..
    }
    
    // We have our standard claims again in `fetchedStdClaims` variable.
}


```