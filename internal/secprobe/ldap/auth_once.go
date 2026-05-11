package ldap

import (
	"context"
	"crypto/tls"
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

var errLDAPAuthenticationFailed = errors.New("ldap bind authentication failed")

type ldapResultError struct {
	code       int
	diagnostic string
}

func (e *ldapResultError) Error() string {
	message := strings.TrimSpace(e.diagnostic)
	if message == "" {
		return fmt.Sprintf("ldap bind failed with result code %d", e.code)
	}
	return fmt.Sprintf("ldap bind failed with result code %d: %s", e.code, message)
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
			ErrorCode:   classifyLDAPFailure(err),
			FindingType: result.FindingTypeCredentialValid,
		}}
	}
	return registrybridge.Attempt{Result: result.Attempt{
		Success:     true,
		Username:    cred.Username,
		Password:    cred.Password,
		Evidence:    "LDAP bind authentication succeeded",
		FindingType: result.FindingTypeCredentialValid,
	}}
}

func authWithCredential(ctx context.Context, target strategy.Target, cred strategy.Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	timeout := timeoutFromContext(ctx)
	conn, err := dialLDAP(ctx, target, timeout)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	stopCancelWatcher := watchContextCancel(ctx, conn)
	defer stopCancelWatcher()

	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	if _, err := conn.Write(bindRequest(1, cred.Username, cred.Password)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}

	packet, err := readBERPacket(conn)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return parseBindResponse(packet)
}

func dialLDAP(ctx context.Context, target strategy.Target, timeout time.Duration) (net.Conn, error) {
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
	return strings.EqualFold(target.Protocol, "ldaps") || target.Port == 636
}

func classifyLDAPFailure(err error) result.ErrorCode {
	if err == nil {
		return ""
	}

	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled), strings.Contains(text, "context canceled"):
		return result.ErrorCodeCanceled
	case errors.Is(err, context.DeadlineExceeded), strings.Contains(text, "deadline exceeded"), strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		return result.ErrorCodeTimeout
	}

	var resultErr *ldapResultError
	if errors.As(err, &resultErr) {
		switch resultErr.code {
		case 0:
			return ""
		case 8, 13, 14, 48:
			return result.ErrorCodeInsufficientConfirmation
		case 49:
			return result.ErrorCodeAuthentication
		default:
			return result.ErrorCodeInsufficientConfirmation
		}
	}

	switch {
	case errors.Is(err, errLDAPAuthenticationFailed),
		strings.Contains(text, "invalid credential"),
		strings.Contains(text, "invalid credentials"),
		strings.Contains(text, "authentication failed"),
		strings.Contains(text, "bind failed"),
		strings.Contains(text, "password"),
		strings.Contains(text, "username"):
		return result.ErrorCodeAuthentication
	case strings.Contains(text, "stronger auth required"),
		strings.Contains(text, "strong authentication required"),
		strings.Contains(text, "confidentiality required"),
		strings.Contains(text, "tls required"),
		strings.Contains(text, "starttls"),
		strings.Contains(text, "strong(er) authentication required"):
		return result.ErrorCodeInsufficientConfirmation
	case strings.Contains(text, "dial"),
		strings.Contains(text, "connect"),
		strings.Contains(text, "connection"),
		strings.Contains(text, "refused"),
		strings.Contains(text, "reset by peer"),
		strings.Contains(text, "no route"),
		strings.Contains(text, "broken pipe"),
		strings.Contains(text, "tls"),
		strings.Contains(text, "eof"):
		return result.ErrorCodeConnection
	default:
		return result.ErrorCodeInsufficientConfirmation
	}
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

func bindRequest(messageID int, username, password string) []byte {
	bindPayload := append(encodeInteger(3), encodeOctetString(username)...)
	bindPayload = append(bindPayload, encodeTLV(0x80, []byte(password))...)

	payload := append(encodeInteger(messageID), encodeTLV(0x60, bindPayload)...)
	return encodeTLV(0x30, payload)
}

func successBindResponse() []byte {
	return bindResponse(1, 0, "", "")
}

func bindResponse(messageID, resultCode int, matchedDN, diagnostic string) []byte {
	response := append(encodeEnumerated(resultCode),
		append(encodeOctetString(matchedDN), encodeOctetString(diagnostic)...)...,
	)
	payload := append(encodeInteger(messageID), encodeTLV(0x61, response)...)
	return encodeTLV(0x30, payload)
}

func parseBindResponse(packet []byte) error {
	tag, outerValue, rest, err := readTLV(packet)
	if err != nil {
		return err
	}
	if tag != 0x30 || len(rest) != 0 {
		return fmt.Errorf("unexpected ldap response envelope")
	}

	_, _, inner, err := readTLV(outerValue)
	if err != nil {
		return err
	}

	tag, bindValue, rest, err := readTLV(inner)
	if err != nil {
		return err
	}
	if tag != 0x61 || len(rest) != 0 {
		return fmt.Errorf("unexpected ldap bind response")
	}

	resultTag, resultValue, remaining, err := readTLV(bindValue)
	if err != nil {
		return err
	}
	if resultTag != 0x0a {
		return fmt.Errorf("unexpected ldap bind result tag")
	}
	code, err := decodeInteger(resultValue)
	if err != nil {
		return err
	}

	_, _, remaining, err = readTLV(remaining)
	if err != nil {
		return err
	}
	diagTag, diagValue, _, err := readTLV(remaining)
	if err != nil {
		return err
	}
	if diagTag != 0x04 {
		return fmt.Errorf("unexpected ldap diagnostic tag")
	}

	if code == 0 {
		return nil
	}

	diagnostic := string(diagValue)
	if code == 49 {
		return fmt.Errorf("%w: %s", errLDAPAuthenticationFailed, strings.TrimSpace(diagnostic))
	}
	return &ldapResultError{code: code, diagnostic: diagnostic}
}

func readLDAPSimpleBind(conn net.Conn) (string, string, error) {
	packet, err := readBERPacket(conn)
	if err != nil {
		return "", "", err
	}

	tag, outerValue, rest, err := readTLV(packet)
	if err != nil {
		return "", "", err
	}
	if tag != 0x30 || len(rest) != 0 {
		return "", "", fmt.Errorf("unexpected ldap message envelope")
	}

	_, _, inner, err := readTLV(outerValue)
	if err != nil {
		return "", "", err
	}

	tag, bindValue, rest, err := readTLV(inner)
	if err != nil {
		return "", "", err
	}
	if tag != 0x60 || len(rest) != 0 {
		return "", "", fmt.Errorf("unexpected ldap bind request")
	}

	_, _, remaining, err := readTLV(bindValue)
	if err != nil {
		return "", "", err
	}
	nameTag, nameValue, remaining, err := readTLV(remaining)
	if err != nil {
		return "", "", err
	}
	if nameTag != 0x04 {
		return "", "", fmt.Errorf("unexpected ldap bind name")
	}
	authTag, authValue, _, err := readTLV(remaining)
	if err != nil {
		return "", "", err
	}
	if authTag != 0x80 {
		return "", "", fmt.Errorf("unexpected ldap auth choice")
	}

	return string(nameValue), string(authValue), nil
}

func readBERPacket(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	length, lengthBytes, err := decodeLength(header[1:], r)
	if err != nil {
		return nil, err
	}

	packet := append([]byte{header[0]}, lengthBytes...)
	value := make([]byte, length)
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, err
	}
	packet = append(packet, value...)
	return packet, nil
}

func decodeLength(initial []byte, r io.Reader) (int, []byte, error) {
	if len(initial) != 1 {
		return 0, nil, fmt.Errorf("invalid ber length prefix")
	}
	first := initial[0]
	if first&0x80 == 0 {
		return int(first), []byte{first}, nil
	}

	count := int(first & 0x7f)
	if count == 0 {
		return 0, nil, fmt.Errorf("indefinite ber lengths are unsupported")
	}

	buf := make([]byte, count)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}

	length := 0
	for _, b := range buf {
		length = (length << 8) | int(b)
	}
	return length, append([]byte{first}, buf...), nil
}

func readTLV(data []byte) (byte, []byte, []byte, error) {
	if len(data) < 2 {
		return 0, nil, nil, fmt.Errorf("truncated ber value")
	}

	tag := data[0]
	length, offset, err := readLengthFromBytes(data[1:])
	if err != nil {
		return 0, nil, nil, err
	}
	start := 1 + offset
	end := start + length
	if end > len(data) {
		return 0, nil, nil, fmt.Errorf("truncated ber payload")
	}
	return tag, data[start:end], data[end:], nil
}

func readLengthFromBytes(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("missing ber length")
	}
	if data[0]&0x80 == 0 {
		return int(data[0]), 1, nil
	}

	count := int(data[0] & 0x7f)
	if count == 0 || len(data) < 1+count {
		return 0, 0, fmt.Errorf("invalid ber length")
	}

	length := 0
	for _, b := range data[1 : 1+count] {
		length = (length << 8) | int(b)
	}
	return length, 1 + count, nil
}

func encodeInteger(value int) []byte {
	if value == 0 {
		return encodeTLV(0x02, []byte{0})
	}

	buf := make([]byte, 0, 4)
	for v := value; v > 0; v >>= 8 {
		buf = append([]byte{byte(v)}, buf...)
	}
	if buf[0]&0x80 != 0 {
		buf = append([]byte{0}, buf...)
	}
	return encodeTLV(0x02, buf)
}

func encodeEnumerated(value int) []byte {
	encoded := encodeInteger(value)
	encoded[0] = 0x0a
	return encoded
}

func encodeOctetString(value string) []byte {
	return encodeTLV(0x04, []byte(value))
}

func encodeTLV(tag byte, value []byte) []byte {
	encoded := []byte{tag}
	encoded = append(encoded, encodeLength(len(value))...)
	encoded = append(encoded, value...)
	return encoded
}

func encodeLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}

	buf := make([]byte, 0, 4)
	for v := length; v > 0; v >>= 8 {
		buf = append([]byte{byte(v)}, buf...)
	}
	return append([]byte{0x80 | byte(len(buf))}, buf...)
}

func decodeInteger(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("empty integer")
	}
	value := 0
	for _, b := range data {
		value = (value << 8) | int(b)
	}
	return value, nil
}
