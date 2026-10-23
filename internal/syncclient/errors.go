package syncclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Errors an *APIError matches by its HTTP status or R11 code.
var (
	ErrBadRequest           = errors.New("syncclient: the server refused the request (400)")
	ErrUnauthorized         = errors.New("syncclient: authentication failed (401)")
	ErrNotFound             = errors.New("syncclient: not found (404)")
	ErrConflict             = errors.New("syncclient: conflict (409)")
	ErrTooLarge             = errors.New("syncclient: a size or collection limit was exceeded (413)")
	ErrRateLimited          = errors.New("syncclient: too many requests (429)")
	ErrQuota                = errors.New("syncclient: the account's storage quota is exhausted (507)")
	ErrServer               = errors.New("syncclient: server error (5xx)")
	ErrRegistrationConflict = errors.New("syncclient: registration conflict")
	ErrAlreadyClaimed       = errors.New("syncclient: the mailbox is claimed by another device")
)

// Errors of the client itself.
var (
	// ErrInsecureURL means the server URL is not https://, or is http://
	// without the loopback development opt-in (R10).
	ErrInsecureURL = errors.New("syncclient: the server must use https://")
	// ErrRedirect means the server redirected to another origin, or too
	// often. Credentials never follow a redirect (R10).
	ErrRedirect = errors.New("syncclient: refused a redirect")
	// ErrTLS means the server's certificate did not verify.
	ErrTLS = errors.New("syncclient: the server's TLS certificate did not verify")
	// ErrUnreachable means the request failed below HTTP: the server could
	// not be reached, or the connection broke or timed out.
	ErrUnreachable = errors.New("syncclient: the server is unreachable")
	// ErrRequestTooLarge means a request body exceeds R8's limit; it was
	// not sent.
	ErrRequestTooLarge = errors.New("syncclient: the request exceeds the server's body limit")
	// ErrResponseTooLarge means a response exceeds the R8/R9 limit for its
	// endpoint; it was discarded.
	ErrResponseTooLarge = errors.New("syncclient: the server's response exceeds its size limit")
	// ErrMalformedResponse means a response does not match its schema
	// under the strict decoder.
	ErrMalformedResponse = errors.New("syncclient: malformed response from the server")
)

// ErrSessionEnded is store.ErrSessionEnded: the server refused a session
// challenge for the device (it is no longer active), or ended the session
// it had just issued.
var ErrSessionEnded = store.ErrSessionEnded

// APIError is an error response from the server: the R11 envelope
// {"error":{"code","message"}}, or only the status when the body is not
// one (a proxy's page, say). It matches the Err* status errors with
// errors.Is.
type APIError struct {
	Status  int
	Code    string // the R11 code; empty when the body was not an R11 error
	Message string
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("syncclient: server answered %d %s", e.Status, http.StatusText(e.Status))
	}
	return fmt.Sprintf("syncclient: server answered %d %s: %s", e.Status, e.Code, e.Message)
}

func (e *APIError) Is(target error) bool {
	switch target {
	case ErrBadRequest:
		return e.Status == http.StatusBadRequest
	case ErrUnauthorized:
		return e.Status == http.StatusUnauthorized
	case ErrNotFound:
		return e.Status == http.StatusNotFound
	case ErrConflict:
		return e.Status == http.StatusConflict
	case ErrTooLarge:
		return e.Status == http.StatusRequestEntityTooLarge
	case ErrRateLimited:
		return e.Status == http.StatusTooManyRequests
	case ErrQuota:
		return e.Status == http.StatusInsufficientStorage
	case ErrServer:
		return e.Status >= 500 && e.Status != http.StatusInsufficientStorage
	case ErrRegistrationConflict:
		return e.Status == http.StatusConflict && e.Code == "registration_conflict"
	case ErrAlreadyClaimed:
		return e.Status == http.StatusConflict && e.Code == "already_claimed"
	}
	return false
}

// Retryable reports whether err is worth retrying later with backoff: a
// rate limit or busy server (429), a server error other than the quota
// (5xx), or a failure to reach the server. Refusals, authentication
// failures, certificate failures and cancellations are not.
func Retryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	var ae *APIError
	if errors.As(err, &ae) {
		return errors.Is(ae, ErrRateLimited) || errors.Is(ae, ErrServer)
	}
	return errors.Is(err, ErrUnreachable)
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorResponse struct {
	Error errorBody `json:"error"`
}

type headConflictResponse struct {
	Error errorBody     `json:"error"`
	Head  vaultlog.Head `json:"head"`
}

// responseError maps a non-200 response. A 409 head_conflict is a
// *store.HeadConflictError with the server's head; one whose head does not
// decode is a malformed response, not a conflict, so a caller never takes
// an unknown outcome for a refusal.
func responseError(status int, body []byte) error {
	if status == http.StatusConflict {
		var hc headConflictResponse
		if canonjson.Unmarshal(body, &hc) == nil && hc.Error.Code == "head_conflict" {
			return &store.HeadConflictError{Head: hc.Head}
		}
	}
	var er errorResponse
	if canonjson.Unmarshal(body, &er) != nil || er.Error.Code == "" {
		return &APIError{Status: status}
	}
	if er.Error.Code == "head_conflict" {
		return fmt.Errorf("%w: a head_conflict error without a head", ErrMalformedResponse)
	}
	return &APIError{Status: status, Code: er.Error.Code, Message: er.Error.Message}
}

// transportError classifies an error of http.Client.Do.
func transportError(err error) error {
	var cve *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	switch {
	case errors.Is(err, ErrRedirect), errors.Is(err, context.Canceled):
		return err
	case errors.As(err, &cve), errors.As(err, &ua), errors.As(err, &he), errors.As(err, &ci):
		return fmt.Errorf("%w: %w", ErrTLS, err)
	}
	return fmt.Errorf("%w: %w", ErrUnreachable, err)
}
