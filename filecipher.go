package licenseclient

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

//Following is for get Plaintext
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("the encrypt string error")
	}
	//get the number of fills
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}

func AesDecrypt(data []byte, key []byte) ([]byte, error) {
	//Create an instance
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//Get block size
	blockSize := block.BlockSize()
	//Decrypt the block using the CBC mode
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	//Initialize the decrypted data receiving slice
	crypted := make([]byte, len(data))
	//Perform decryption
	blockMode.CryptBlocks(crypted, data)
	//Remove padding
	crypted, err = pkcs7UnPadding(crypted)
	if err != nil {
		return nil, err
	}
	return crypted, nil
}


func DecryptByAes(data string) ([]byte, error) {
	dataByte, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	return AesDecrypt(dataByte, PwdKey)
}

//Following is for signature verify
func ReadParsePublicKey() (*rsa.PublicKey, error) {
	Kbytes := []byte(Kstring)
	block, _ := pem.Decode(Kbytes)
	if block == nil {
		return nil, errors.New("the public key error")
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	return publicKey, nil
}

func RSAVerify(data []byte, base64Sig string) error {
	decryptByte, err := base64.StdEncoding.DecodeString(base64Sig)
	if err != nil {
		return err
	}
	hashAlgorithm := crypto.SHA256
	hashInstance := hashAlgorithm.New()
	hashInstance.Write(data)
	hashed := hashInstance.Sum(nil)
	publicKey, err := ReadParsePublicKey()
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(publicKey, hashAlgorithm, hashed, decryptByte)
}

//Following is for get request code
//pkcs7Padding filling
func pkcs7Padding(data []byte, blockSize int) []byte {
	//check the missed length. At least 1,at most the blockSize
	padding := blockSize - len(data)%blockSize
	//Make up the digits. Copy count of padding slices
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

//AesEncrypt
func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	//Create an encrypted instance
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//Determine the size of the encrypted block
	blockSize := block.BlockSize()
	//filling to the block
	encryptBytes := pkcs7Padding(data, blockSize)
	//Initialize encrypted data receiving slice
	crypted := make([]byte, len(encryptBytes))
	//Use the cbc encryption mode
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	//Perform encryption operation
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}


//AES encrypt for the data
func EncryptByAes(data []byte) (string, error) {
	res, err := AesEncrypt(data, PwdKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(res), nil
}


