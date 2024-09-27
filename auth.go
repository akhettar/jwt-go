package jwt

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	jwtgo "github.com/golang-jwt/jwt/v5"
)

var (
	// ErrorAuthHeaderEmpty thrown when an empty Authorization header is received
	ErrorAuthHeaderEmpty = errors.New("auth header empty")

	// ErrorInvalidAuthHeader thrown when an invalid Authorization header is received
	ErrorInvalidAuthHeader = errors.New("invalid auth header")
)

const (

	// AuthenticateHeader the Gin authenticate header
	AuthenticateHeader = "WWW-Authenticate"

	// AuthorizationHeader the auth header that gets passed to all services
	AuthorizationHeader = "Authorization"

	// BearerSchema the type of token expected
	BearerSchema = "Bearer "

	// HEADER used by the JWT middle ware
	HEADER = "header"
)

// AuthMiddleware middleware
type AuthMiddleware struct {

	// User can define own Unauthorized func.
	Unauthorized func(*gin.Context, int, string)

	Timeout time.Duration

	// TokenLookup the header name of the token
	TokenLookup string

	// IsBearerSchema when the authorization token use a Bearer schema
	IsBearerSchema bool

	// DebugLog extra logging
	DebugLog bool

	// TimeFunc
	TimeFunc func() time.Time

	// Realm name to display to the user. Required.
	Realm string

	// to verify issuer
	VerifyIssuer bool

	// The issuer
	Iss string

	// JWK public JSON Web Key (JWK) for your user pool
	JWK map[string]JWKKey

	// skipTokenUseValidation is a flag that determines whether the "token_use" claim validation should be skipped.
	// If set to true, the "token_use" claim will not be checked during the JWT claims validation process.
	skipTokenUseValidation bool
}

// JWK is json data struct for JSON Web Key
type JWK struct {
	Keys []JWKKey
}

// JWKKey is json data struct for cognito jwk key
type JWKKey struct {
	Alg string
	E   string
	Kid string
	Kty string
	N   string
	Use string
}

// AuthError auth error response
type AuthError struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// MiddlewareInit initialize jwt configs.
func (mw *AuthMiddleware) MiddlewareInit() {

	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:" + AuthorizationHeader
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	if mw.Unauthorized == nil {
		mw.Unauthorized = func(c *gin.Context, code int, message string) {
			c.JSON(code, AuthError{Code: code, Message: message})
		}
	}

	if mw.Realm == "" {
		mw.Realm = "gin jwt"
	}
}

func (mw *AuthMiddleware) middlewareImpl(c *gin.Context) {

	// Parse the given token
	var tokenStr string
	var err error

	parts := strings.Split(mw.TokenLookup, ":")
	switch parts[0] {
	case HEADER:
		tokenStr, err = mw.jwtFromHeader(c, parts[1])
	}

	if err != nil {
		log.Printf("JWT token Parser error: %s", err.Error())
		mw.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	token, err := mw.parse(tokenStr)

	if err != nil {
		log.Printf("JWT token Parser error: %s", err.Error())
		mw.unauthorized(c, http.StatusUnauthorized, err.Error())
		return
	}

	c.Set("JWT_TOKEN", token)
	c.Next()
}

func (mw *AuthMiddleware) jwtFromHeader(c *gin.Context, key string) (string, error) {
	authHeader := c.Request.Header.Get(key)

	if authHeader == "" {
		return "", ErrorAuthHeaderEmpty
	}

	if mw.IsBearerSchema {
		authHeader = mw.jwtBearer([]byte(authHeader))
	}

	return authHeader, nil
}

func (mw *AuthMiddleware) jwtBearer(strToken []byte) string {
	bearer := []byte(BearerSchema)
	if bytes.HasPrefix(strToken, bearer) {
		jwt := string(strToken[len(bearer):])
		return jwt
	}
	return string(strToken)
}

func (mw *AuthMiddleware) unauthorized(c *gin.Context, code int, message string) {
	if mw.Realm == "" {
		mw.Realm = "gin jwt"
	}
	c.Header(AuthenticateHeader, "JWT realm="+mw.Realm)
	c.Abort()

	mw.Unauthorized(c, code, message)
}

// MiddlewareFunc implements the Middleware interface.
func (mw *AuthMiddleware) MiddlewareFunc() gin.HandlerFunc {
	// initialise
	mw.MiddlewareInit()
	return func(c *gin.Context) {
		mw.middlewareImpl(c)
	}
}

// AuthJWTMiddleware create an instance of the middle ware function
func AuthJWTMiddleware(iss string, jwk map[string]JWKKey, opts ...Option) (*AuthMiddleware, error) {
	authMiddleware := &AuthMiddleware{
		Timeout: time.Hour,

		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, AuthError{Code: code, Message: message})
		},

		// Token header
		TokenLookup: "header:" + AuthorizationHeader,
		TimeFunc:    time.Now,
		JWK:         jwk,
		Iss:         iss,
	}

	for _, opt := range opts {
		opt(authMiddleware)
	}

	return authMiddleware, nil
}

// Option defines a function type that modifies the AuthMiddleware.
type Option func(query *AuthMiddleware)

// WithSkipTokenUseValidation returns an Option that sets the skipTokenUseValidation field in AuthMiddleware.
// This option allows skipping the validation of the token_use claim in JWT tokens.
func WithSkipTokenUseValidation(skipTokenUseValidation bool) Option {
	return func(query *AuthMiddleware) {
		query.skipTokenUseValidation = skipTokenUseValidation
	}
}

func (mw *AuthMiddleware) parse(tokenStr string) (*jwtgo.Token, error) {

	// 1. Decode the token string into JWT format.
	token, err := jwtgo.Parse(tokenStr, func(token *jwtgo.Token) (interface{}, error) {

		// cognito user pool : RS256
		if _, ok := token.Method.(*jwtgo.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// 5. Get the kid from the JWT token header and retrieve the corresponding JSON Web Key that was stored
		if kid, ok := token.Header["kid"]; ok {
			if kidStr, ok := kid.(string); ok {
				key := mw.JWK[kidStr]
				// 6. Verify the signature of the decoded JWT token.
				rsaPublicKey := convertKey(key.E, key.N)
				return rsaPublicKey, nil
			}
		}

		// rsa public key
		return "", nil
	})

	if err != nil {
		return token, err
	}

	claims := token.Claims.(jwtgo.MapClaims)

	_, ok := claims["iss"]
	if !ok {
		return token, fmt.Errorf("token does not contain issuer")
	}
	err = mw.validateJwtClaims(claims)
	if err != nil {
		return token, err
	}

	if token.Valid {
		return token, nil
	}
	return token, err
}

// validateJwtClaims validates the JWT claims provided in the token.
// It performs the following checks:
// 1. Validates the "iss" claim to ensure it matches the expected issuer.
// 2. Optionally validates the "token_use" claim if skipTokenUseValidation is false.
// 3. Validates the "exp" claim to ensure the token is not expired.
// If any of these validations fail, an error is returned.
func (mw *AuthMiddleware) validateJwtClaims(claims jwtgo.MapClaims) error {
	var err error
	// 3. Check the iss claim. It should match your user pool.
	err = validateClaimItem("iss", []string{mw.Iss}, claims)
	if err != nil {
		Error.Printf("Failed to validate the jwt token claims %v", err)
		return err
	}

	// 4. Check the token_use claim.
	if !mw.skipTokenUseValidation {
		err = validateTokenUse(claims)
		if err != nil {
			return err
		}
	}

	// 7. Check the exp claim and make sure the token is not expired.
	err = validateExpired(claims, mw.DebugLog)
	if err != nil {
		return err
	}

	return nil
}

func validateClaimItem(key string, keyShouldBe []string, claims jwtgo.MapClaims) error {
	if val, ok := claims[key]; ok {
		if valStr, ok := val.(string); ok {
			for _, shouldbe := range keyShouldBe {
				if valStr == shouldbe {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("%v does not match any of valid values: %v", key, keyShouldBe)
}

func validateExpired(claims jwtgo.MapClaims, debugLog bool) error {
	if tokenExp, ok := claims["exp"]; ok {
		if exp, ok := tokenExp.(float64); ok {
			now := time.Now().Unix()
			if debugLog {
				fmt.Printf("current unixtime : %v\n", now)
				fmt.Printf("expire unixtime  : %v\n", int64(exp))
			}

			if int64(exp) > now {
				return nil
			}
		}
		return errors.New("cannot parse token exp")
	}
	return errors.New("token is expired")
}

// validateTokenUse checks the "token_use" claim in the JWT claims.
// It ensures that the "token_use" claim is either "id" or "access".
// If the claim is not present or does not match the expected values, an error is returned.
func validateTokenUse(claims jwtgo.MapClaims) error {
	if tokenUse, ok := claims["token_use"]; ok {
		if tokenUseStr, ok := tokenUse.(string); ok {
			if tokenUseStr == "id" || tokenUseStr == "access" {
				return nil
			}
		}
	}
	return errors.New("token_use should be id or access")
}

func convertKey(rawE, rawN string) *rsa.PublicKey {
	decodedE, err := base64.RawURLEncoding.DecodeString(rawE)
	if err != nil {
		panic(err)
	}
	if len(decodedE) < 4 {
		ndata := make([]byte, 4)
		copy(ndata[4-len(decodedE):], decodedE)
		decodedE = ndata
	}
	pubKey := &rsa.PublicKey{
		N: &big.Int{},
		E: int(binary.BigEndian.Uint32(decodedE[:])),
	}
	decodedN, err := base64.RawURLEncoding.DecodeString(rawN)
	if err != nil {
		panic(err)
	}
	pubKey.N.SetBytes(decodedN)
	return pubKey
}

// Download the json web public key for the given user pool id
func GetJWK(jwkURL string) (map[string]JWKKey, error) {
	Info.Printf("Downloading the jwk from the given url %s", jwkURL)
	jwk := &JWK{}

	var myClient = &http.Client{Timeout: 10 * time.Second}
	r, err := myClient.Get(jwkURL)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(jwk); err != nil {
		return nil, err
	}

	jwkMap := make(map[string]JWKKey, 0)
	for _, jwk := range jwk.Keys {
		jwkMap[jwk.Kid] = jwk
	}
	return jwkMap, nil
}
