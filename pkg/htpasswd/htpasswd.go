package htpasswd

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
)

type passwordFile struct {
	passwords map[string]string
}

func newPasswordFile(data []byte) (*passwordFile, error) {
	bytes.Split(data, []byte{'\n'})
	f := &passwordFile{
		passwords: make(map[string]string),
	}
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		parts := strings.Split(l, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid number of tokens")
		}
		username := strings.TrimSpace(parts[0])
		password := strings.TrimSpace(parts[1])
		if _, ok := f.passwords[username]; ok {
			return nil, fmt.Errorf("username %q already exists", username)
		}
		f.passwords[username] = password
	}
	return f, nil
}

// ListUsers ...
func (f *passwordFile) ListUsers() ([]string, error) {
	var users []string
	for username := range f.passwords {
		users = append(users, username)
	}
	return users, nil
}

func (f *passwordFile) DeleteUser(username string) error {
	if _, ok := f.passwords[username]; !ok {
		return fmt.Errorf("user %q does not exist", username)
	}
	delete(f.passwords, username)
	return nil
}

// SetPassword ...
func (f *passwordFile) SetPassword(username, password string) error {
	hash := sha1.New()
	if _, err := hash.Write([]byte(password)); err != nil {
		return err
	}
	f.passwords[username] = "{SHA}" + base64.StdEncoding.EncodeToString(hash.Sum(nil))
	return nil
}

// Bytes ...
func (f *passwordFile) Bytes() []byte {
	var buf bytes.Buffer
	for user, pass := range f.passwords {
		buf.WriteString(user + ":" + pass + "\n")
	}
	return buf.Bytes()
}
