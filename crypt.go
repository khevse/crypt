package crypt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

// @param is_encrypting: true = encrypt; false = decrypt
func RSACrypt(is_encrypting bool, key interface{}, rsa_length int, data []byte, label []byte) (*bytes.Buffer, error) {

	var max_block_len int
	switch rsa_length {
	case 4096:
		if is_encrypting {
			max_block_len = 446
		} else {
			max_block_len = 512
		}

	case 2048:
		if is_encrypting {
			max_block_len = 190
		} else {
			max_block_len = 256
		}
	default:
		return nil, errors.New("Wrong RSA length")
	}

	var buf bytes.Buffer
	var start_pos, end_pos int

	sha := sha256.New()

	for end_pos < len(data) {
		start_pos = end_pos
		end_pos = start_pos + max_block_len
		if end_pos > len(data) {
			end_pos = len(data)
		}

		block := data[start_pos:end_pos]

		var err error
		var resut []byte

		if is_encrypting {
			resut, err = rsa.EncryptOAEP(sha, rand.Reader, key.(*rsa.PublicKey), block, label)
		} else {
			resut, err = rsa.DecryptOAEP(sha, rand.Reader, key.(*rsa.PrivateKey), block, label)
		}

		if err != nil {
			return nil, err
		}

		buf.Write(resut)
	}

	return &buf, nil
}

func RSAGenerateLabel() ([]byte, error) {

	label := make([]byte, 32)
	if _, err := rand.Read(label); err != nil {
		return nil, errors.New("Failed generating label: " + err.Error())
	}

	return label, nil
}

func ReadPem(path_to_file string, key interface{}) error {

	pem_data, err := ioutil.ReadFile(path_to_file)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(pem_data)
	if block == nil {
		return errors.New("Decode error: " + path_to_file)
	}

	switch key.(type) {
	case **rsa.PrivateKey:
		{
			switch block.Type {
			case "RSA PRIVATE KEY":
				rsa_key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return err
				}
				*(key.(**rsa.PrivateKey)) = rsa_key
			default:
				return fmt.Errorf("Unsupported key type %q", block.Type)
			}
		}
	case **rsa.PublicKey:
		{
			switch block.Type {
			case "PUBLIC KEY":
				rsa_key, err := x509.ParsePKIXPublicKey(block.Bytes)
				if err != nil {
					return err
				}
				*(key.(**rsa.PublicKey)) = rsa_key.(*rsa.PublicKey)
			default:
				return fmt.Errorf("Unsupported key type %q", block.Type)
			}
		}
	}

	return nil
}
