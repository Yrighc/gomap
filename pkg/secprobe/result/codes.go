package result

import "strings"

type ErrorCode string

const (
	ErrorCodeAuthentication           ErrorCode = "authentication"
	ErrorCodeConnection               ErrorCode = "connection"
	ErrorCodeTimeout                  ErrorCode = "timeout"
	ErrorCodeCanceled                 ErrorCode = "canceled"
	ErrorCodeInsufficientConfirmation ErrorCode = "insufficient_confirmation"
)

type FindingType string

const (
	FindingTypeCredentialValid    FindingType = "credential_valid"
	FindingTypeUnauthorizedAccess FindingType = "unauthorized_access"
)

func ParseErrorCode(raw string) (ErrorCode, bool) {
	switch normalizeCode(raw) {
	case string(ErrorCodeAuthentication):
		return ErrorCodeAuthentication, true
	case string(ErrorCodeConnection):
		return ErrorCodeConnection, true
	case string(ErrorCodeTimeout):
		return ErrorCodeTimeout, true
	case string(ErrorCodeCanceled):
		return ErrorCodeCanceled, true
	case string(ErrorCodeInsufficientConfirmation):
		return ErrorCodeInsufficientConfirmation, true
	default:
		return "", false
	}
}

func ParseFindingType(raw string) (FindingType, bool) {
	switch normalizeCode(raw) {
	case string(FindingTypeCredentialValid):
		return FindingTypeCredentialValid, true
	case string(FindingTypeUnauthorizedAccess):
		return FindingTypeUnauthorizedAccess, true
	default:
		return "", false
	}
}

func LegacyErrorCode(code ErrorCode) string {
	return strings.ReplaceAll(string(code), "_", "-")
}

func LegacyFindingType(kind FindingType) string {
	return strings.ReplaceAll(string(kind), "_", "-")
}

func normalizeCode(raw string) string {
	return strings.ReplaceAll(strings.TrimSpace(raw), "-", "_")
}
