package result

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
