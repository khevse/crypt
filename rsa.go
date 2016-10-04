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

func ReadPemFromFile(path_to_file string, key interface{}) error {

	pem_data, err := ioutil.ReadFile(path_to_file)
	if err != nil {
		return err
	}

	return ReadPem(pem_data, key)
}

func ReadPem(pem_data []byte, key interface{}) error {

	pem_key, _ := pem.Decode(pem_data)
	if pem_key == nil {
		return errors.New("Failed decoding  pem.")
	}

	switch key.(type) {
	case **rsa.PrivateKey:
		{
			switch pem_key.Type {
			case "RSA PRIVATE KEY":
				rsa_key, err := x509.ParsePKCS1PrivateKey(pem_key.Bytes)
				if err != nil {
					return err
				}

				*(key.(**rsa.PrivateKey)) = rsa_key
			default:
				return fmt.Errorf("Unsupported key type %q", pem_key.Type)
			}
		}
	case **rsa.PublicKey:
		{
			switch pem_key.Type {
			case "PUBLIC KEY":
				rsa_key, err := x509.ParsePKIXPublicKey(pem_key.Bytes)
				if err != nil {
					return err
				}

				*(key.(**rsa.PublicKey)) = rsa_key.(*rsa.PublicKey)
			default:
				return fmt.Errorf("Unsupported key type %q", pem_key.Type)
			}
		}
	}

	return nil
}

func RSAEncrypt(key *rsa.PublicKey, data []byte, label []byte) (*bytes.Buffer, error) {
	return crypt(true, key, data, label)
}

func RSADecrypt(key *rsa.PrivateKey, data []byte, label []byte) (*bytes.Buffer, error) {
	return crypt(false, key, data, label)
}

func crypt(encrypting bool, key interface{}, data []byte, label []byte) (*bytes.Buffer, error) {

	block_len, err := RSABlockLen(encrypting, key)
	if err != nil {
		return nil, errors.New("Wrong RSA length")
	}

	var buf bytes.Buffer
	var start_pos, end_pos int

	sha := sha256.New()

	for end_pos < len(data) {
		start_pos = end_pos
		end_pos = start_pos + block_len
		if end_pos > len(data) {
			end_pos = len(data)
		}

		block := data[start_pos:end_pos]

		var err error
		var resut []byte

		if encrypting {
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

func RSABlockLen(encrypting bool, key interface{}) (int, error) {

	var rsa_length int

	if encrypting {
		rsa_length = key.(*rsa.PublicKey).N.BitLen()
	} else {
		rsa_length = key.(*rsa.PrivateKey).N.BitLen()
	}

	var block_len int

	switch rsa_length {
	case 4096:
		block_len = 512
	case 2048:
		block_len = 256
	default:
		return -1, errors.New("Wrong RSA length")
	}

	if encrypting {
		block_len -= 66
	}

	return block_len, nil
}
