package auth

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/context"
)

type digestClient struct {
	nc       uint64
	lastSeen int64
}

// DigestAuth digest auth struct
type DigestAuth struct {
	Realm            string
	Opaque           string
	Secrets          SecretProvider
	PlainTextSecrets bool
	IgnoreNonceCount bool
	// Headers used by authenticator. Set to ProxyHeaders to use with
	// proxy server. When nil, NormalHeaders are used.
	Headers *Headers

	/*
	   Approximate size of Client's Cache. When actual number of
	   tracked client nonces exceeds
	   ClientCacheSize+ClientCacheTolerance, ClientCacheTolerance*2
	   older entries are purged.
	*/
	ClientCacheSize      int
	ClientCacheTolerance int

	clients map[string]*digestClient
	mutex   sync.Mutex
}

// check that DigestAuth implements AuthenticatorInterface
var _ = (AuthenticatorInterface)((*DigestAuth)(nil))

type digestCacheEntry struct {
	nonce    string
	lastSeen int64
}

type digestCache []digestCacheEntry

func (c digestCache) Less(i, j int) bool {
	return c[i].lastSeen < c[j].lastSeen
}

func (c digestCache) Len() int {
	return len(c)
}

func (c digestCache) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

// Purge Remove count oldest entries from DigestAuth.clients
func (a *DigestAuth) Purge(count int) {
	entries := make([]digestCacheEntry, 0, len(a.clients))
	for nonce, client := range a.clients {
		entries = append(entries, digestCacheEntry{nonce, client.lastSeen})
	}
	cache := digestCache(entries)
	sort.Sort(cache)
	for _, client := range cache[:count] {
		delete(a.clients, client.nonce)
	}
}

// RequireAuth is a http.Handler for DigestAuth which initiates the authentication process
// (or requires reauthentication).
func (a *DigestAuth) RequireAuth(w http.ResponseWriter, r *http.Request) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if len(a.clients) > a.ClientCacheSize+a.ClientCacheTolerance {
		a.Purge(a.ClientCacheTolerance * 2)
	}
	nonce := RandomKey()
	a.clients[nonce] = &digestClient{nc: 0, lastSeen: time.Now().UnixNano()}
	w.Header().Set(contentType, a.Headers.V().UnauthContentType)
	w.Header().Set(a.Headers.V().Authenticate,
		fmt.Sprintf(`Digest realm="%s", nonce="%s", opaque="%s", algorithm="MD5", qop="auth"`,
			a.Realm, nonce, a.Opaque))
	w.WriteHeader(a.Headers.V().UnauthCode)
	w.Write([]byte(a.Headers.V().UnauthResponse))
}

// DigestAuthParams Parse Authorization header from the http.Request. Returns a map of
// auth parameters or nil if the header is not a valid parsable Digest
// auth header.
func DigestAuthParams(authorization string) map[string]string {
	s := strings.SplitN(authorization, " ", 2)
	if len(s) != 2 || s[0] != "Digest" {
		return nil
	}

	return ParsePairs(s[1])
}

// CheckAuth Check if request contains valid authentication data. Returns a pair
// of username, authinfo where username is the name of the authenticated
// user or an empty string and authinfo is the contents for the optional
// Authentication-Info response header.
func (a *DigestAuth) CheckAuth(r *http.Request) (username string, authinfo *string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	username = ""
	authinfo = nil
	auth := DigestAuthParams(r.Header.Get(a.Headers.V().Authorization))
	if auth == nil {
		return "", nil
	}
	// RFC2617 Section 3.2.1 specifies that unset value of algorithm in
	// WWW-Authenticate Response header should be treated as
	// "MD5". According to section 3.2.2 the "algorithm" value in
	// subsequent Request Authorization header must be set to whatever
	// was supplied in the WWW-Authenticate Response header. This
	// implementation always returns an algorithm in WWW-Authenticate
	// header, however there seems to be broken clients in the wild
	// which do not set the algorithm. Assume the unset algorithm in
	// Authorization header to be equal to MD5.
	if _, ok := auth["algorithm"]; !ok {
		auth["algorithm"] = "MD5"
	}
	if a.Opaque != auth["opaque"] || auth["algorithm"] != "MD5" || auth["qop"] != "auth" {
		return "", nil
	}

	// Check if the requested URI matches auth header
	if r.RequestURI != auth["uri"] {
		// We allow auth["uri"] to be a full path prefix of request-uri
		// for some reason lost in history, which is probably wrong, but
		// used to be like that for quite some time
		// (https://tools.ietf.org/html/rfc2617#section-3.2.2 explicitly
		// says that auth["uri"] is the request-uri).
		//
		// TODO: make an option to allow only strict checking.
		switch u, err := url.Parse(auth["uri"]); {
		case err != nil:
			return "", nil
		case r.URL == nil:
			return "", nil
		case len(u.Path) > len(r.URL.Path):
			return "", nil
		case !strings.HasPrefix(r.URL.Path, u.Path):
			return "", nil
		}
	}

	HA1 := a.Secrets(auth["username"], a.Realm)
	if a.PlainTextSecrets {
		HA1 = H(auth["username"] + ":" + a.Realm + ":" + HA1)
	}
	HA2 := H(r.Method + ":" + auth["uri"])
	KD := H(strings.Join([]string{HA1, auth["nonce"], auth["nc"], auth["cnonce"], auth["qop"], HA2}, ":"))

	if subtle.ConstantTimeCompare([]byte(KD), []byte(auth["response"])) != 1 {
		return "", nil
	}

	// At this point crypto checks are completed and validated.
	// Now check if the session is valid.

	nc, err := strconv.ParseUint(auth["nc"], 16, 64)
	if err != nil {
		return "", nil
	}

	client, ok := a.clients[auth["nonce"]]
	if !ok {
		return "", nil
	}

	if client.nc != 0 && client.nc >= nc && !a.IgnoreNonceCount {
		return "", nil
	}

	client.nc = nc
	client.lastSeen = time.Now().UnixNano()

	//respHA2 := H(":" + auth["uri"])
	//rspauth := H(strings.Join([]string{HA1, auth["nonce"], auth["nc"], auth["cnonce"], auth["qop"], respHA2}, ":"))

	info := fmt.Sprintf(`qop="auth", rspauth="%s", cnonce="%s", nc="%s"`,
		string(auth["response"]), auth["cnonce"], auth["nc"])
	return auth["username"], &info
}

// DefaultClientCacheSize Default values for ClientCacheSize
const DefaultClientCacheSize = 1000

// DefaultClientCacheTolerance default values for ClientCacheTolerance for DigestAuth
const DefaultClientCacheTolerance = 100

// Wrap returns an Authenticator which uses HTTP Digest
// authentication. Arguments:
//
// realm: The authentication realm.
//
// secrets: SecretProvider which must return HA1 digests for the same
// realm as above.
func (a *DigestAuth) Wrap(wrapped AuthenticatedHandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if username, authinfo := a.CheckAuth(r); username == "" {
			a.RequireAuth(w, r)
		} else {
			ar := &AuthenticatedRequest{Request: *r, Username: username}
			if authinfo != nil {
				w.Header().Set(a.Headers.V().AuthInfo, *authinfo)
			}
			wrapped(w, ar)
		}
	}
}

// JustCheck returns function which converts an http.HandlerFunc into a
// http.HandlerFunc which requires authentication. Username is passed as
// an extra X-Authenticated-Username header.
func (a *DigestAuth) JustCheck(wrapped http.HandlerFunc) http.HandlerFunc {
	return a.Wrap(func(w http.ResponseWriter, ar *AuthenticatedRequest) {
		ar.Header.Set(AuthUsernameHeader, ar.Username)
		wrapped(w, &ar.Request)
	})
}

// NewContext returns a context carrying authentication information for the request.
func (a *DigestAuth) NewContext(ctx context.Context, r *http.Request) context.Context {
	username, authinfo := a.CheckAuth(r)
	info := &Info{Username: username, ResponseHeaders: make(http.Header)}
	if username != "" {
		info.Authenticated = true
		info.ResponseHeaders.Set(a.Headers.V().AuthInfo, *authinfo)
	} else {
		// return back digest WWW-Authenticate header
		if len(a.clients) > a.ClientCacheSize+a.ClientCacheTolerance {
			a.Purge(a.ClientCacheTolerance * 2)
		}
		nonce := RandomKey()
		a.clients[nonce] = &digestClient{nc: 0, lastSeen: time.Now().UnixNano()}
		info.ResponseHeaders.Set(a.Headers.V().Authenticate,
			fmt.Sprintf(`Digest realm="%s", nonce="%s", opaque="%s", algorithm="MD5", qop="auth"`,
				a.Realm, nonce, a.Opaque))
	}
	return context.WithValue(ctx, infoKey, info)
}

// NewDigestAuthenticator create a new digest auth struct
func NewDigestAuthenticator(realm string, secrets SecretProvider) *DigestAuth {
	da := &DigestAuth{
		Opaque:               RandomKey(),
		Realm:                realm,
		Secrets:              secrets,
		PlainTextSecrets:     false,
		ClientCacheSize:      DefaultClientCacheSize,
		ClientCacheTolerance: DefaultClientCacheTolerance,
		clients:              map[string]*digestClient{}}
	return da
}
