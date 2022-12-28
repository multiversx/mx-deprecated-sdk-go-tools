package main

import (
	"C"
)

func main() {
}

//export generatePublicKey
func generatePublicKey(seed *C.char) *C.char {
	seedString := C.GoString(seed)
	publicKey := doGeneratePublicKey(seedString)
	return C.CString(publicKey)
}

//export signMessage
func signMessage(messageToSign *C.char, seed *C.char) *C.char {
	messageToSignString := C.GoString(messageToSign)
	seedString := C.GoString(seed)
	signature := doSignMessage(messageToSignString, seedString)
	return C.CString(signature)
}

//export verifyMessage
func verifyMessage(publicKey *C.char, messageToVerify *C.char, signature *C.char) int {
	publicKeyString := C.GoString(publicKey)
	messageToVerifyString := C.GoString(messageToVerify)
	signatureString := C.GoString(signature)
	ok := doVerifyMessage(publicKeyString, messageToVerifyString, signatureString)
	if ok {
		return 1
	}

	return 0
}

//export generatePrivateKey
func generatePrivateKey() *C.char {
	privateKey := doGeneratePrivateKey()
	return C.CString(privateKey)
}
