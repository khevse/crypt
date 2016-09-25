package crypt

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestRSA(t *testing.T) {

	const (
		path_to_public_pem  = "public.pem"
		path_to_private_pem = "private.pem"
	)

	var err error
	var public *rsa.PublicKey
	var private *rsa.PrivateKey

	for _, rsa_length := range []int{2048, 4096} {
		err = generateKeys(rsa_length)
		if err != nil {
			t.Error(err.Error())
		}

		if err = ReadPem(path_to_public_pem, &public); err != nil {
			t.Error(err.Error())
		}

		if err = ReadPem(path_to_private_pem, &private); err != nil {
			t.Error(err.Error())
		}

		var label []byte
		if label, err = RSAGenerateLabel(); err != nil {
			t.Error(err.Error())
		}

		for i, key := range []*rsa.PublicKey{public, &private.PublicKey} {

			for _, length := range []int{1, 128, 512, 1024, 5000, 15000} {
				text := generateText(length).Bytes()

				encrypt_data, err := RSACrypt(true, key, rsa_length, text, label)
				if err != nil {
					t.Errorf("Encrypt (key:%d, rsa: %d, data: %d) %s", i, rsa_length, length, err.Error())
				}

				decript_data, err := RSACrypt(false, private, rsa_length, encrypt_data.Bytes(), label)
				if err != nil {
					t.Errorf("Decrypt (key:%d, rsa: %d, data: %d) %s", i, rsa_length, length, err.Error())
				}

				if bytes.Compare(decript_data.Bytes(), text) != 0 {
					t.Errorf("Failed test (key:%d, rsa: %d, data: %d) %v != %v", i, rsa_length, length, decript_data.Bytes(), text)
				}
			}

		}

		for _, path := range []string{path_to_private_pem, path_to_public_pem} {
			_, err := os.Stat(path)
			if err == nil {
				os.RemoveAll(path)
			}
		}
	}

}

func generateKeys(length int) error {

	cmd := exec.Command("openssl", "genrsa", "-out", "private.pem", fmt.Sprintf("%d", length))
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("openssl", "rsa", "-in", "private.pem", "-outform", "PEM", "-pubout", "-out", "public.pem")
	if err := cmd.Run(); err != nil {
		return err
	}

	return nil
}

func generateText(length int) *bytes.Buffer {

	var buf bytes.Buffer

	for i := 0; i < length; i++ {
		buf.WriteString("a")
	}

	return &buf
}
