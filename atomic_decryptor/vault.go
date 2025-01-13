package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"os"
)

// settings for Atomic Wallet Vaults

// AtomicVault struct
type Vault struct {
	EncryptedData []byte
	Hash          string
	Decrypted     int32
}

// decryption sanity check
func isValid(s []byte) bool {
	notPrintable := bytes.IndexFunc(s, func(r rune) bool {
		return r < 32 || r > 126
	})
	return notPrintable == -1
}

// derives AES key and IV using MD5 and supplied password / salt
func deriveKeyAndIV(password, salt []byte) (key, iv []byte) {
	mdf := md5.New()

	// first hash
	mdf.Write(password)
	mdf.Write(salt)
	hash1 := mdf.Sum(nil)

	// second hash
	mdf.Reset()
	mdf.Write(hash1)
	mdf.Write(password)
	mdf.Write(salt)
	hash2 := mdf.Sum(nil)

	// third hash
	mdf.Reset()
	mdf.Write(hash2)
	mdf.Write(password)
	mdf.Write(salt)
	hash3 := mdf.Sum(nil)

	// combine hashes to form full key and IV
	fullKey := make([]byte, 0, 48) // set capacity to avoid reallocation
	fullKey = append(fullKey, hash1...)
	fullKey = append(fullKey, hash2...)
	fullKey = append(fullKey, hash3...)
	key = fullKey[:32]
	iv = fullKey[32:48]

	return key, iv
}

// decrypt vault
func decryptVault(encryptedData, password []byte) (decryptedData []byte, err error) {
	if len(encryptedData) < 16 {
		return nil, fmt.Errorf("encrypted data is too short to contain salt and data")
	}
	salt := encryptedData[8:16]
	content := encryptedData[16:]

	if len(content)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("encrypted data is not a multiple of the block size")
	}

	key, iv := deriveKeyAndIV(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decryptedData = make([]byte, len(content))
	mode.CryptBlocks(decryptedData, content)

	// check and remove PKCS7 padding
	padLength := int(decryptedData[len(decryptedData)-1])
	if padLength > aes.BlockSize || padLength == 0 || padLength > len(decryptedData) {
		return nil, fmt.Errorf("invalid padding size")
	}
	decryptedData = decryptedData[:len(decryptedData)-padLength]

	return decryptedData, nil
}

// parse vault
func readVaultData(filePath string) ([]Vault, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var vaults []Vault
	scanner := bufio.NewScanner(file)

	prefix := []byte("U2FsdGVkX1")

	for scanner.Scan() {
		line := scanner.Bytes()

		line = bytes.TrimSpace(line)

		if !bytes.HasPrefix(line, prefix) {
			continue
		}

		decodedData, err := base64.StdEncoding.DecodeString(string(line))
		if err != nil {
			fmt.Println("Error decoding base64 data:", err)
			continue
		}

		vaults = append(vaults, Vault{
			EncryptedData: decodedData,
			Hash:          string(line),
		})
	}

	return vaults, nil
}
