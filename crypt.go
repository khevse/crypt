package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
)

func GenerateRandomBytes() ([]byte, error) {

	retval := make([]byte, 32)
	if _, err := rand.Read(retval); err != nil {
		return nil, errors.New("Failed generating random bytes: " + err.Error())
	}

	return retval, nil
}

func Encrypt(key *rsa.PublicKey, data []byte, label []byte) (*bytes.Buffer, error) {

	aes_key, err := GenerateRandomBytes()
	if err != nil {
		return nil, err
	}

	encrypted_data, iv, err := AESEncrypt(aes_key, data)
	if err != nil {
		return nil, err
	}

	aes_secret := bytes.NewBuffer(iv)
	aes_secret.Write(aes_key)

	block, err := RSAEncrypt(key, aes_secret.Bytes(), label)

	encrypt := bytes.NewBuffer(block.Bytes())
	encrypt.Write(encrypted_data)

	return encrypt, err
}

func Decrypt(key *rsa.PrivateKey, data []byte, label []byte) (*bytes.Buffer, error) {

	block_len, err := RSABlockLen(false, key)
	if err != nil {
		return nil, err
	}

	aes_secret, err := RSADecrypt(key, data[:block_len], label)
	if err != nil {
		return nil, err
	}

	iv := aes_secret.Bytes()[:aes.BlockSize]
	aes_key := aes_secret.Bytes()[aes.BlockSize:]

	decrypted_data, err := AESDecrypt(aes_key, iv, data[block_len:])
	if err != nil {
		return nil, err
	}

	return bytes.NewBuffer(decrypted_data), nil
}
