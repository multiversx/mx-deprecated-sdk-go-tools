package main

import (
	"C"
	"encoding/hex"
	"log"

	"github.com/ElrondNetwork/elrond-go/crypto/signing"
	"github.com/ElrondNetwork/elrond-go/crypto/signing/mcl"
	"github.com/ElrondNetwork/elrond-go/crypto/signing/mcl/singlesig"
)

func main() {
}

//export generatePrivateKey
func generatePrivateKey() *C.char {
	privateKey := doGeneratePrivateKey()

	return C.CString(privateKey)
}

func doGeneratePrivateKey() string {
	keyGenerator := signing.NewKeyGenerator(mcl.NewSuiteBLS12())
	privateKey, _ := keyGenerator.GeneratePair()
	privateKeyBytes, err := privateKey.ToByteArray()
	if err != nil {
		log.Println("doGeneratePrivateKey(): error when decoding the private key", err)
		return ""
	}

	return hex.EncodeToString(privateKeyBytes)
}

//export generatePublicKey
func generatePublicKey(seed *C.char) *C.char {
	seedString := C.GoString(seed)
	publicKey := doGeneratePublicKey(seedString)

	return C.CString(publicKey)
}

func doGeneratePublicKey(seedString string) string {
	keyGenerator := signing.NewKeyGenerator(mcl.NewSuiteBLS12())

	seed, err := hex.DecodeString(seedString)
	if err != nil {
		log.Println("doGeneratePublicKey(): error when decoding the seed", err)
		return ""
	}

	privateKey, err := keyGenerator.PrivateKeyFromByteArray(seed)
	if err != nil {
		log.Println("doGeneratePublicKey(): error when creating the private key", err)
		return ""
	}

	publicKey := privateKey.GeneratePublic()
	publicKeyBytes, err := publicKey.ToByteArray()
	if err != nil {
		log.Println("doGeneratePublicKey(): error when decoding the public key", err)
		return ""
	}

	return hex.EncodeToString(publicKeyBytes)
}

//export signMessage
func signMessage(messageToSign *C.char, seed *C.char) *C.char {
	messageToSignString := C.GoString(messageToSign)
	seedString := C.GoString(seed)
	signature := doSignMessage(messageToSignString, seedString)

	return C.CString(signature)
}

func doSignMessage(messageToSignString string, seedString string) string {
	singleSigner := singlesig.BlsSingleSigner{}
	keyGenerator := signing.NewKeyGenerator(mcl.NewSuiteBLS12())

	messageToSign, err := hex.DecodeString(messageToSignString)
	if err != nil {
		log.Println("doSignMessage(): error when decoding the message", err)
		return ""
	}

	seed, err := hex.DecodeString(seedString)
	if err != nil {
		log.Println("doSignMessage(): error when decoding the seed", err)
		return ""
	}

	privateKey, err := keyGenerator.PrivateKeyFromByteArray(seed)
	if err != nil {
		log.Println("doSignMessage(): error when creating the private key", err)
		return ""
	}

	signature, err := singleSigner.Sign(privateKey, messageToSign)
	if err != nil {
		log.Println("doSignMessage(): error when signing the message", err)
		return ""
	}

	return hex.EncodeToString(signature)
}

//export verifyMessage
func verifyMessage(publicKey *C.char, messageToVerify *C.char, signature *C.char) int {
	publicKeyString := C.GoString(publicKey)
	messageToVerifyString := C.GoString(messageToVerify)
	signatureString := C.GoString(signature)
	ok := doVerifyMessage(publicKeyString, messageToVerifyString, signatureString)
	if ok {
		return 0x01
	}

	return 0x00
}

func doVerifyMessage(publicKeyString string, messageToVerifyString string, signatureString string) bool {
	singleSigner := singlesig.BlsSingleSigner{}
	keyGenerator := signing.NewKeyGenerator(mcl.NewSuiteBLS12())

	publicKeyBytes, err := hex.DecodeString(publicKeyString)
	if err != nil {
		log.Println("doVerifyMessage(): error when decoding the seed", err)
		return false
	}

	messageToVerify, err := hex.DecodeString(messageToVerifyString)
	if err != nil {
		log.Println("doVerifyMessage(): error when decoding the message", err)
		return false
	}

	signature, err := hex.DecodeString(signatureString)
	if err != nil {
		log.Println("doVerifyMessage(): error when decoding the signature", err)
		return false
	}

	publicKey, err := keyGenerator.PublicKeyFromByteArray(publicKeyBytes)
	if err != nil {
		log.Println("doVerifyMessage(): error when creating the public key", err)
		return false
	}

	err = singleSigner.Verify(publicKey, messageToVerify, signature)
	return err == nil
}
