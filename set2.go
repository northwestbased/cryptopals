package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"log"
	"math/rand"
	"strings"
	"reflect"
)

//Implements PKS#7 padding
func Pad(pt []byte, blockLength int) []byte {
	neededBytes := blockLength - (len(pt) % blockLength)
	if neededBytes == 0 {
		neededBytes = len(pt)
	}
	for i := 0; i < neededBytes; i++ {
		pt = append(pt, byte(neededBytes))
	}
	return pt
}

func AESInCBCModeEncrypt(pt, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	bs := cipher.BlockSize()
	dst := make([]byte, 16, 16)

	var out []byte

	blocks := BreakIntoBlocks(pt, bs)

	for i := 0; i < len(blocks); i++ {
		block := blocks[i]
		if i > 0 {
			block, _ = XOrBuffers(block, out[bs*(i-1):bs*i])
		} else {
			block, _ = XOrBuffers(block, iv)
		}
		cipher.Encrypt(dst, block)
		out = append(out, dst...)
	}
	return out
}

func AESInCBCModeDecrypt(ct, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	bs := cipher.BlockSize()
	dst := make([]byte, 16, 16)

	var out []byte

	blocks := BreakIntoBlocks(ct, bs)

	for i := 0; i < len(blocks); i++ {
		var pt []byte
		block := blocks[i]
		cipher.Decrypt(dst, block)

		if i > 0 {
			pt, _ = XOrBuffers(dst, blocks[i-1])
		} else {
			pt, _ = XOrBuffers(dst, iv)
		}
		out = append(out, pt...)
	}

	return out
}

//encryption function
func AESInECBModeEncrypt(ct, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	bs := cipher.BlockSize()
	if len(ct)%bs != 0 {
		panic("Ciphertext length needs to be a multiple of the blocksize")
	}
	dst := make([]byte, 16, 16)
	var out []byte

	for i := 0; i < len(ct); i += bs {
		cipher.Encrypt(dst, ct[i:i+bs])
		out = append(out, dst[:]...)
	}

	return out
}

func CBCOrECBEncrypt(pt []byte) []byte {
	doECB := rand.Int31n(2) == 1

	prefixByteLength := rand.Int31n(5) + 5
	postfixByteLength := rand.Int31n(5) + 5

	prefixBytes := make([]byte, prefixByteLength)
	postfixBytes := make([]byte, postfixByteLength)
	key := make([]byte, 16)

	rand.Read(postfixBytes)
	rand.Read(prefixBytes)
	rand.Read(key)
	pt = append(prefixBytes, pt...)
	pt = append(pt, postfixBytes...)

	pt = Pad(pt, 16)
	if doECB {
		log.Println("Encrypting with ECB mode...")
		return AESInECBModeEncrypt(pt, key[:])
	} else {
		log.Println("Encrypting with CBC mode...")
		iv := make([]byte, 16)
		rand.Read(iv)
		return AESInCBCModeEncrypt(pt, key[:], iv[:])
	}
}

func DetectAESOrECB() {
	pt := make([]byte, 100, 100)
	ct := CBCOrECBEncrypt(pt)
	if AESInECBModeOracle(ct) {
		log.Println("ECB mode detected")
	} else {
		log.Println("CBC mode detected")
	}
}

func ECBWithUnknownSuffix() func([]byte) []byte {

	unknownPt := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
	"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
	"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
	"YnkK"

	unknownPtDecoded, _ := base64.StdEncoding.DecodeString(unknownPt)

	key := make([]byte, 16)
	rand.Read(key)

	return func(pt []byte) []byte {
		pt = append(pt, []byte(unknownPtDecoded)...)
		pt = Pad(pt, 16)
		return AESInECBModeEncrypt(pt, key)
	}
}

//finds the block size of a block cipher returns the 
//block size, and the padding for the last block of the ciphertext
func findBlockSizeAndPadding(encrypter func([]byte)[]byte) (int, int) {
	var payload []byte
	startingLength := len(encrypter(payload))
	currentLength := startingLength
	for startingLength == currentLength {
		payload = append(payload, byte('A'))
		currentLength = len(encrypter(payload))
	}
	blockLength := currentLength - startingLength
	paddingLength := len(payload)
	return blockLength, paddingLength
}

func AttackECBSuffix() []byte {
	encrypter := ECBWithUnknownSuffix()
	//Discover the block size of the cipher.

	blockSize, paddingLength := findBlockSizeAndPadding(encrypter)
	//Detect that the function is using ECB
	payload := make([]byte, blockSize*2, blockSize*2)
	ct := encrypter(payload)
	if !AESInECBModeOracle(ct) {
		panic("ECB mode not detected")
	}

	//Recover the plaintext
	payload = make([]byte, 16, 16)
	plaintext := []byte{}
	ctLength := len(encrypter([]byte("")))

	//for blockStart := 0; blockStart < ctLength; blockStart+=blockSize {
	for blockStart := 0; blockStart < ctLength; blockStart+=blockSize {
		blockEnd := blockStart + blockSize
		isLastBlock := blockEnd == ctLength
		plaintextBlock := []byte("")

		/* get plaintext for each block */
		for i := blockStart; i < blockEnd; i++ {
			payload = payload[1:]

			/* deal with dynamic padding values for the last block */
			if isLastBlock && len(plaintextBlock) + paddingLength > 16 {
				paddingVal := len(plaintextBlock) + paddingLength - 15
				for i := len(plaintextBlock) - 1; i > len(plaintextBlock) - paddingVal; i-- {
					plaintextBlock[i] = byte(paddingVal)
				}
			}

			/* build block map */
			blockMap := make(map[string]string)
			for i := 0; i < 256; i++ {

				fullBlock := append(payload, plaintextBlock...)
				fullBlock = append(fullBlock, byte(i))

				encryptedBlock := string(encrypter(fullBlock)[0:blockSize])
				blockMap[encryptedBlock] = string(fullBlock)
			}

			payloadEncrypted := encrypter(payload)[blockStart:blockEnd]
			foundPlaintext := blockMap[string(payloadEncrypted)]
			lastByte := foundPlaintext[15]
			plaintextBlock = append(plaintextBlock, lastByte)
		}

		payload = plaintextBlock
		plaintext = append(plaintext, plaintextBlock...)
	}

	return plaintext
}



func profileFor(email string) string {
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)
	return "email=" + email + "&uid=10&role=user"
}

func initProfileFunctions() (func([]byte) []byte, func([]byte)) {
	key := make([]byte, 16)
	rand.Read(key)
	encrypt := func(profile []byte) []byte {
		profile = Pad(profile, 16)
		return AESInECBModeEncrypt(profile, key)
	}
	decrypt := func(profile []byte) {
		decodedProfile := AESInECBMode(profile, key)
		pairs := strings.Split(string(decodedProfile), "&")
		for _, p := range pairs {
			k := strings.Split(p, "=")
			log.Println(k)
		}
	}
	return encrypt, decrypt
}

func ECBWithUnknownSuffixAndPrefix() func ([]byte) []byte {
	unknownPt := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
	"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
	"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
	"YnkK"
	unknownPtDecoded, _ := base64.StdEncoding.DecodeString(unknownPt)

	randomCount := rand.Int31n(100) + 32
	prefix := make([]byte, randomCount)
	rand.Read(prefix)

	key := make([]byte, 16)
	rand.Read(key)

	return func(pt []byte) []byte {
		pt = append(pt, []byte(unknownPtDecoded)...)
		pt = append(prefix, pt...)
		pt = Pad(pt, 16)
		return AESInECBModeEncrypt(pt, key)
	}
}



func AttackECBSuffixWithPrefix() []byte {
	encrypter := ECBWithUnknownSuffixAndPrefix()
	//Discover the block size of the cipher.

	blockSize, paddingLength := findBlockSizeAndPadding(encrypter)
	//Detect that the function is using ECB
	payload := make([]byte, blockSize*3, blockSize*3)
	ct := encrypter(payload)
	if !AESInECBModeOracle(ct) {
		panic("ECB mode not detected")
	}

	offsetLength := 0
	for !AESInECBModeOracle(encrypter(make([]byte, offsetLength))) {
		offsetLength += 1
	}
	offsetLength = offsetLength % blockSize



	offset := make([]byte,offsetLength)
	log.Println("offsetlen", offsetLength)

	ct = encrypter(make([]byte, blockSize * 2 + offsetLength))
	blocks := BreakIntoBlocks(ct, blockSize)
	ourStart := 0
	for i := 0; i < len(blocks) - 1; i++ {
		if reflect.DeepEqual(blocks[i], blocks[i+1]) {
			ourStart = i * 16
			break
		}
	}
	log.Println("ourStart", ourStart)

	paddingLength -= offsetLength

	//Recover the plaintext
	payload = make([]byte, 16, 16)
	plaintext := []byte{}
	ctLength := len(encrypter([]byte("")))


	for blockStart := ourStart; blockStart < ctLength; blockStart+=blockSize {
		blockEnd := blockStart + blockSize
		isLastBlock := blockEnd == ctLength
		plaintextBlock := []byte("")

		/* get plaintext for each block */
		for i := blockStart; i < blockEnd; i++ {
			payload = payload[1:]

			/* deal with dynamic padding values for the last block */
			if isLastBlock && len(plaintextBlock) + paddingLength > 16 {
				paddingVal := len(plaintextBlock) + paddingLength - 15
				for i := len(plaintextBlock) - 1; i > len(plaintextBlock) - paddingVal; i-- {
					plaintextBlock[i] = byte(paddingVal)
				}
			}

			/* build block map */
			blockMap := make(map[string]string)
			for i := 0; i < 256; i++ {

				fullBlock := append(payload, plaintextBlock...)
				fullBlock = append(fullBlock, byte(i))

				encryptedBlock := string(encrypter(append(offset, fullBlock...))[ourStart:ourStart+blockSize])
				blockMap[encryptedBlock] = string(fullBlock)
			}

			payloadEncrypted := encrypter(append(offset, payload...))[blockStart:blockEnd]
			foundPlaintext := blockMap[string(payloadEncrypted)]
			lastByte := foundPlaintext[15]
			plaintextBlock = append(plaintextBlock, lastByte)
		}

		payload = plaintextBlock
		log.Println(string(plaintextBlock))
		plaintext = append(plaintext, plaintextBlock...)
	}

	return plaintext
}

