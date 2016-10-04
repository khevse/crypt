package crypt

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

const (
	path_to_public_pem  = "public.pem"
	path_to_private_pem = "private.pem"
)

func TestCrypt(t *testing.T) {

	var err error
	var public *rsa.PublicKey
	var private *rsa.PrivateKey

	for _, rsa_length := range []int{2048, 4096} {
		public, private = getKeys(rsa_length)

		var label []byte
		if label, err = GenerateRandomBytes(); err != nil {
			t.Error(err.Error())
		}

		for i, key := range []*rsa.PublicKey{public, &private.PublicKey} {

			for _, length := range []int{1, 16, 17, 128, 512, 1024, 5000, 15000} {
				text := generateText(length)

				// [1] RSA
				{
					encrypt_data, err := RSAEncrypt(key, text.Bytes(), label)
					if err != nil {
						t.Errorf("Encrypt (key:%d, rsa: %d, data: %d) %s", i, length, err.Error())
					}

					decript_data, err := RSADecrypt(private, encrypt_data.Bytes(), label)
					if err != nil {
						t.Errorf("Decrypt (key:%d, rsa: %d, data: %d) %s", i, length, err.Error())
					}

					if bytes.Compare(decript_data.Bytes(), text.Bytes()) != 0 {
						t.Errorf("Failed test (key:%d, rsa: %d, data: %d) %v != %v", i, length, decript_data.Bytes(), text.Bytes())
					}
				}

				// [2] AES
				{
					aes_key := label

					encrypt_data, iv, err := AESEncrypt(aes_key, text.Bytes())
					if err != nil {
						t.Errorf("AES: %v", err)
						break
					}

					decrypt_data, err := AESDecrypt(aes_key, iv, encrypt_data)
					if err != nil {
						t.Errorf("AES: %v", err)
						break
					}

					if !bytes.Equal(decrypt_data, text.Bytes()) {
						t.Errorf("AES: %v != %v", decrypt_data, text.Bytes())
						break
					}
				}

				// [3] AES & RSA
				{
					encrypt_data, err := Encrypt(key, text.Bytes(), label)
					if err != nil {
						t.Errorf("Encrypt (key:%d, rsa: %d, data: %d) %s", i, length, err.Error())
					}

					decript_data, err := Decrypt(private, encrypt_data.Bytes(), label)
					if err != nil {
						t.Errorf("Decrypt (key:%d, rsa: %d, data: %d) %s", i, length, err.Error())
					}

					if bytes.Compare(decript_data.Bytes(), text.Bytes()) != 0 {
						t.Errorf("Failed test (key:%d, rsa: %d, data: %d) %v != %v", i, length, decript_data.Bytes(), text)
					}
				}
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

func generateText(length int) *bytes.Buffer {

	var buf bytes.Buffer

	for i := 0; i < length; i++ {
		if i%2 == 0 {
			buf.WriteString("a")
		} else {
			buf.WriteString("b")
		}
	}

	return &buf
}

func generateSymplyRSAKeys(length int) error {

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

func getKeys(rsa_length int) (*rsa.PublicKey, *rsa.PrivateKey) {

	var public *rsa.PublicKey
	var private *rsa.PrivateKey

	err := generateSymplyRSAKeys(rsa_length)
	if err != nil {
		panic(err.Error())
	}

	if err = ReadPemFromFile(path_to_public_pem, &public); err != nil {
		panic(err.Error())
	}

	if err = ReadPemFromFile(path_to_private_pem, &private); err != nil {
		panic(err.Error())
	}

	return public, private
}
