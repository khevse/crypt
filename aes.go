package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

/**
 * Data encryption using AES
 * @param key  []byte secret key
 * @param data []byte source data for encryption
 *
 * @result 1. encrypted data in format [4]byte + []byte
 *            (where first four bytes are length of the source data, from the fifth byte is encrypted data)
 *         2. initialize vector (16 bytes)
 *         3. error
 */
func AESEncrypt(key []byte, data []byte) ([]byte, []byte, error) {

	if len(data) == 0 {
		return nil, nil, errors.New("Empty data for encrypting.")
	}

	cipher_block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	add_to_end_block := 0
	if len(data)%aes.BlockSize != 0 {
		count_blocks := int(len(data) / aes.BlockSize)
		add_to_end_block = aes.BlockSize - (len(data) - count_blocks*aes.BlockSize)
	}

	data_len := int32ToBytes(int32(len(data)))
	encrypt_data := make([]byte, len(data_len)+len(data)+add_to_end_block) // min 20 bytes - 4+16
	copy(encrypt_data, data_len)

	mode := cipher.NewCBCEncrypter(cipher_block, iv)

	var start_pos, end_pos, block_num int

	for end_pos < len(data) {
		start_pos = end_pos
		end_pos = start_pos + aes.BlockSize
		encrypt_start_pos := aes.BlockSize*block_num + len(data_len)
		block_num += 1

		if end_pos >= len(data) {
			block := make([]byte, aes.BlockSize)
			copy(block, data[start_pos:])
			mode.CryptBlocks(encrypt_data[encrypt_start_pos:], block)
		} else {
			mode.CryptBlocks(encrypt_data[encrypt_start_pos:], data[start_pos:end_pos])
		}

	}

	return encrypt_data, iv, nil
}

/**
 * Data decryption using AES
 * @param key  []byte secret key
 * @param iv   []byte initialize vector
 * @param data []byte encrypted data in format [4]byte + []byte
 *             (where first four bytes are length of the source data, from the fifth byte is encrypted data)
 *
 * @result 1. decrypted data in format []byte
 *         2. error
 */
func AESDecrypt(key []byte, iv []byte, data []byte) ([]byte, error) {

	const result_len_bytes int = 4

	if len(data) == 0 {
		return nil, errors.New("Empty data for decrypting.")
	}

	if (len(data)-result_len_bytes)%aes.BlockSize != 0 {
		return nil, errors.New("Wrong encrypt data length.")
	}

	cipher_block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result_len := bytesToInt32(data[:result_len_bytes])

	stream := cipher.NewCBCDecrypter(cipher_block, iv)
	decrypt_data := bytes.NewBuffer(nil)
	start_pos, end_pos := result_len_bytes, result_len_bytes

	for end_pos < len(data) {
		start_pos = end_pos
		end_pos = start_pos + aes.BlockSize

		block := data[start_pos:end_pos]
		stream.CryptBlocks(block, block)
		decrypt_data.Write(block)
	}

	return decrypt_data.Bytes()[:result_len], nil
}

func int32ToBytes(val int32) []byte {

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, val)
	return buf.Bytes()
}

func bytesToInt32(val []byte) (retval int32) {

	buf := bytes.NewBuffer(val)
	binary.Read(buf, binary.LittleEndian, &retval)
	return
}
