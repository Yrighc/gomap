package kafka

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	registrybridge "github.com/yrighc/gomap/pkg/secprobe/registry"
	"github.com/yrighc/gomap/pkg/secprobe/result"
	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

const (
	kafkaAPIVersionSASLHandshake    int16 = 1
	kafkaAPIVersionSASLAuthenticate int16 = 0
	kafkaAPIKeySASLHandshake        int16 = 17
	kafkaAPIKeySASLAuthenticate     int16 = 36
	kafkaSASLMechanism                    = "PLAIN"
)

var (
	errKafkaAuthenticationFailed = errors.New("kafka sasl authentication failed")
	errKafkaUnsupportedMechanism = errors.New("kafka broker does not support sasl/plain")
)

type kafkaResponseError struct {
	code    int16
	message string
}

func (e *kafkaResponseError) Error() string {
	if strings.TrimSpace(e.message) == "" {
		return fmt.Sprintf("kafka response error code %d", e.code)
	}
	return fmt.Sprintf("kafka response error code %d: %s", e.code, strings.TrimSpace(e.message))
}

type Authenticator struct {
	auth func(context.Context, strategy.Target, strategy.Credential) error
}

func NewAuthenticator(auth func(context.Context, strategy.Target, strategy.Credential) error) Authenticator {
	if auth == nil {
		auth = authWithCredential
	}
	return Authenticator{auth: auth}
}

func (a Authenticator) AuthenticateOnce(ctx context.Context, target strategy.Target, cred strategy.Credential) registrybridge.Attempt {
	if err := a.auth(ctx, target, cred); err != nil {
		return registrybridge.Attempt{Result: result.Attempt{
			Error:       err.Error(),
			ErrorCode:   classifyKafkaFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "Kafka SASL authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	timeout := timeoutFromContext(ctx)
	conn, err := dialKafka(ctx, target, timeout)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	stopCancelWatcher := watchContextCancel(ctx, conn)
	defer stopCancelWatcher()

	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	correlationID := int32(1)
	if err := writeKafkaRequest(conn, kafkaAPIKeySASLHandshake, kafkaAPIVersionSASLHandshake, correlationID, "gomap-secprobe", encodeKafkaString(kafkaSASLMechanism)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err := verifyHandshakeResponse(conn, correlationID); err != nil {
		return err
	}

	correlationID++
	payload := buildPlainAuthPayload(cred.Username, cred.Password)
	if err := writeKafkaRequest(conn, kafkaAPIKeySASLAuthenticate, kafkaAPIVersionSASLAuthenticate, correlationID, "gomap-secprobe", encodeKafkaBytes(payload)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return verifyAuthenticateResponse(conn, correlationID)
}

func dialKafka(ctx context.Context, target strategy.Target, timeout time.Duration) (net.Conn, error) {
	addr := net.JoinHostPort(target.IP, strconv.Itoa(target.Port))
	dialer := &net.Dialer{Timeout: timeout}
	if shouldUseTLS(target) {
		serverName := target.Host
		if serverName == "" {
			serverName = target.IP
		}
		return (&tls.Dialer{
			NetDialer: dialer,
			Config: &tls.Config{
				ServerName:         serverName,
				InsecureSkipVerify: true,
			},
		}).DialContext(ctx, "tcp", addr)
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

func shouldUseTLS(target strategy.Target) bool {
	return target.Port == 9093 || strings.Contains(strings.ToLower(target.Protocol), "ssl")
}

func classifyKafkaFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}

	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	case errors.Is(err, errKafkaUnsupportedMechanism),
		strings.Contains(text, "unsupported sasl"),
		strings.Contains(text, "unsupported mechanism"),
		strings.Contains(text, "mechanism") && strings.Contains(text, "plain"):
		return result.ErrorCodeInsufficientConfirmation
	case errors.Is(err, errKafkaAuthenticationFailed),
		strings.Contains(text, "sasl authentication failed"),
		strings.Contains(text, "authentication failed"),
		strings.Contains(text, "invalid credentials"),
		strings.Contains(text, "invalid username"),
		strings.Contains(text, "invalid password"):
		return result.ErrorCodeAuthentication
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "reset by peer"),
		strings.Contains(text, "no route"),
		strings.Contains(text, "broken pipe"),
		strings.Contains(text, "eof"),
		strings.Contains(text, "tls"):
		return result.ErrorCodeConnection
	default:
		return result.ErrorCodeInsufficientConfirmation
	}
}

func verifyHandshakeResponse(conn net.Conn, correlationID int32) error {
	body, err := readKafkaResponseBody(conn, correlationID)
	if err != nil {
		return err
	}
	if len(body) < 2 {
		return io.ErrUnexpectedEOF
	}

	errorCode := int16(binary.BigEndian.Uint16(body[:2]))
	rest := body[2:]
	if errorCode != 0 {
		return handshakeError(errorCode)
	}

	mechanisms, err := decodeKafkaStringArray(rest)
	if err != nil {
		return err
	}
	for _, mechanism := range mechanisms {
		if strings.EqualFold(mechanism, kafkaSASLMechanism) {
			return nil
		}
	}
	return errKafkaUnsupportedMechanism
}

func verifyAuthenticateResponse(conn net.Conn, correlationID int32) error {
	body, err := readKafkaResponseBody(conn, correlationID)
	if err != nil {
		return err
	}
	if len(body) < 2 {
		return io.ErrUnexpectedEOF
	}

	errorCode := int16(binary.BigEndian.Uint16(body[:2]))
	rest := body[2:]
	message, rest, err := decodeKafkaNullableString(rest)
	if err != nil {
		return err
	}
	_, _, err = decodeKafkaBytesField(rest)
	if err != nil {
		return err
	}
	if errorCode == 0 {
		return nil
	}
	return authenticateError(errorCode, message)
}

func handshakeError(code int16) error {
	switch code {
	case 33:
		return errKafkaUnsupportedMechanism
	default:
		return &kafkaResponseError{code: code}
	}
}

func authenticateError(code int16, message string) error {
	switch code {
	case 58:
		if strings.TrimSpace(message) == "" {
			message = "sasl authentication failed"
		}
		return fmt.Errorf("%w: %s", errKafkaAuthenticationFailed, strings.TrimSpace(message))
	case 33:
		return errKafkaUnsupportedMechanism
	default:
		return &kafkaResponseError{code: code, message: message}
	}
}

func writeKafkaRequest(conn net.Conn, apiKey, apiVersion int16, correlationID int32, clientID string, body []byte) error {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header[0:2], uint16(apiKey))
	binary.BigEndian.PutUint16(header[2:4], uint16(apiVersion))
	binary.BigEndian.PutUint32(header[4:8], uint32(correlationID))
	payload := append(header, encodeKafkaString(clientID)...)
	payload = append(payload, body...)

	frame := make([]byte, 4, 4+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)
	_, err := conn.Write(frame)
	return err
}

func readKafkaResponseBody(conn net.Conn, correlationID int32) ([]byte, error) {
	frame, err := readKafkaFrame(conn)
	if err != nil {
		return nil, err
	}
	if len(frame) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	gotCorrelationID := int32(binary.BigEndian.Uint32(frame[:4]))
	if gotCorrelationID != correlationID {
		return nil, fmt.Errorf("unexpected kafka correlation id: got %d want %d", gotCorrelationID, correlationID)
	}
	return frame[4:], nil
}

func readKafkaFrame(r io.Reader) ([]byte, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(r, sizeBuf[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint32(sizeBuf[:]))
	if size < 0 {
		return nil, errors.New("negative kafka frame size")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func decodeKafkaStringArray(data []byte) ([]string, error) {
	if len(data) < 4 {
		return nil, io.ErrUnexpectedEOF
	}
	count := int(int32(binary.BigEndian.Uint32(data[:4])))
	rest := data[4:]
	values := make([]string, 0, count)
	for i := 0; i < count; i++ {
		value, next, err := readKafkaStringField(rest)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		rest = next
	}
	return values, nil
}

func decodeKafkaNullableString(data []byte) (string, []byte, error) {
	if len(data) < 2 {
		return "", nil, io.ErrUnexpectedEOF
	}
	length := int(int16(binary.BigEndian.Uint16(data[:2])))
	if length == -1 {
		return "", data[2:], nil
	}
	if length < 0 || len(data) < 2+length {
		return "", nil, io.ErrUnexpectedEOF
	}
	return string(data[2 : 2+length]), data[2+length:], nil
}

func decodeKafkaBytesField(data []byte) ([]byte, []byte, error) {
	if len(data) < 4 {
		return nil, nil, io.ErrUnexpectedEOF
	}
	length := int(int32(binary.BigEndian.Uint32(data[:4])))
	if length == -1 {
		return nil, data[4:], nil
	}
	if length < 0 || len(data) < 4+length {
		return nil, nil, io.ErrUnexpectedEOF
	}
	return append([]byte(nil), data[4:4+length]...), data[4+length:], nil
}

func readKafkaStringField(data []byte) (string, []byte, error) {
	if len(data) < 2 {
		return "", nil, io.ErrUnexpectedEOF
	}
	length := int(int16(binary.BigEndian.Uint16(data[:2])))
	if length < 0 || len(data) < 2+length {
		return "", nil, io.ErrUnexpectedEOF
	}
	return string(data[2 : 2+length]), data[2+length:], nil
}

func encodeKafkaString(value string) []byte {
	buf := make([]byte, 2, 2+len(value))
	binary.BigEndian.PutUint16(buf, uint16(len(value)))
	return append(buf, value...)
}

func encodeKafkaBytes(value []byte) []byte {
	buf := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint32(buf, uint32(len(value)))
	return append(buf, value...)
}

func buildPlainAuthPayload(username, password string) []byte {
	payload := make([]byte, 0, len(username)+len(password)+2)
	payload = append(payload, 0)
	payload = append(payload, username...)
	payload = append(payload, 0)
	payload = append(payload, password...)
	return payload
}

func timeoutFromContext(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if timeout := time.Until(deadline); timeout > 0 {
			return timeout
		}
	}
	return 0
}

func watchContextCancel(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	return func() {
		close(done)
	}
}
