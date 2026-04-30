package result

type Attempt struct {
	Success     bool
	Username    string
	Password    string
	Evidence    string
	Error       string
	ErrorCode   ErrorCode
	FindingType FindingType
}
