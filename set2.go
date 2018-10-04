package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"errors"
	"log"
	"reflect"
	"strings"
)

//Pad implements PKS#7 padding. It returns a padded version of pt
//based on blockSize.
func Pad(pt []byte, blockSize int) []byte {
	paddingLength := blockSize - (len(pt) % blockSize)
	//if the last block doesn't need any padding,
	//create a block that only contains padding
	//bytes
	if paddingLength == 0 {
		paddingLength = blockSize
	}

	for i := 0; i < paddingLength; i++ {
		pt = append(pt, byte(paddingLength))
	}
	return pt
}

func AESInCBCModeEncrypt(pt, key, iv []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	bs := cipher.BlockSize() //should always return 16
	dst := make([]byte, bs)

	var out []byte

	blocks := BreakIntoBlocks(pt, bs)

	for i := 0; i < len(blocks); i++ {
		block := blocks[i]
		if i > 0 {
			prevBlock := out[bs*(i-1) : bs*i]
			block = XOr(block, prevBlock)
		} else {
			block = XOr(block, iv)
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
	dst := make([]byte, bs)

	var out []byte

	blocks := BreakIntoBlocks(ct, bs)

	for i := 0; i < len(blocks); i++ {
		var pt []byte
		block := blocks[i]
		cipher.Decrypt(dst, block)

		if i > 0 {
			pt = XOr(dst, blocks[i-1])
		} else {
			pt = XOr(dst, iv)
		}
		out = append(out, pt...)
	}

	return out
}

func AESInECBModeEncrypt(ct, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	bs := cipher.BlockSize()
	if len(ct)%bs != 0 {
		panic("Ciphertext length needs to be a multiple of the blocksize")
	}
	dst := make([]byte, bs)
	var out []byte

	for i := 0; i < len(ct); i += bs {
		cipher.Encrypt(dst, ct[i:i+bs])
		out = append(out, dst[:]...)
	}

	return out
}

func CBCOrECBEncrypt(pt []byte) []byte {
	doECB := GetRandomInt(2) == 1

	prefixByteLength := GetRandomInt(5) + 5
	postfixByteLength := GetRandomInt(5) + 5

	prefixBytes := Key(prefixByteLength)
	postfixBytes := Key(postfixByteLength)
	key := Key(16)

	pt = append(prefixBytes, pt...)
	pt = append(pt, postfixBytes...)

	pt = Pad(pt, 16)
	if doECB {
		log.Println("Encrypting with ECB mode...")
		return AESInECBModeEncrypt(pt, key[:])
	} else {
		log.Println("Encrypting with CBC mode...")
		iv := Key(16)
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

	unknownB64 := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

	unknown, err := base64.StdEncoding.DecodeString(unknownB64)
	if err != nil {
		panic(err)
	}

	key := Key(16)

	return func(pt []byte) []byte {
		pt = append(pt, []byte(unknown)...)
		pt = Pad(pt, 16)
		return AESInECBModeEncrypt(pt, key)
	}
}

//finds the block size of a block cipher. returns the
//block size and the original padding for the last block of the ciphertext
func findBlockSizeAndPadding(encrypter func([]byte) []byte) (int, int) {
	var payload []byte
	startingLength := len(encrypter(payload))
	currentLength := startingLength
	for startingLength == currentLength {
		payload = append(payload, byte('A'))
		currentLength = len(encrypter(payload))
	}
	blockSize := currentLength - startingLength
	paddingLength := len(payload)
	return blockSize, paddingLength
}

//admittedly, this function is a bit messy...
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
	pt := []byte{}
	ctLength := len(encrypter([]byte("")))

	//for blockStart := 0; blockStart < ctLength; blockStart+=blockSize {
	for blockStart := 0; blockStart < ctLength; blockStart += blockSize {
		blockEnd := blockStart + blockSize
		isLastBlock := blockEnd == ctLength
		ptBlock := []byte("")

		/* get plaintext for each block */
		for i := blockStart; i < blockEnd; i++ {
			payload = payload[1:]

			/* deal with dynamic padding values for the last block */
			if isLastBlock && len(ptBlock)+paddingLength > 16 {
				paddingVal := len(ptBlock) + paddingLength - 15
				for i := len(ptBlock) - 1; i > len(ptBlock)-paddingVal; i-- {
					ptBlock[i] = byte(paddingVal)
				}
			}

			/* build block map */
			blockMap := make(map[string]string)
			for i := 0; i < 256; i++ {

				fullBlock := append(payload, ptBlock...)
				fullBlock = append(fullBlock, byte(i))

				encryptedBlock := string(encrypter(fullBlock)[0:blockSize])
				blockMap[encryptedBlock] = string(fullBlock)
			}

			payloadEncrypted := encrypter(payload)[blockStart:blockEnd]
			foundPlaintext := blockMap[string(payloadEncrypted)]
			lastByte := foundPlaintext[15]
			ptBlock = append(ptBlock, lastByte)
		}

		payload = ptBlock
		pt = append(pt, ptBlock...)
	}

	return pt
}

func profileFor(email string) string {
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)
	return "email=" + email + "&uid=10&role=user"
}

func initProfileEncryption() (func([]byte) []byte, func([]byte) bool) {
	key := Key(16)
	encrypt := func(profile []byte) []byte {
		profile = Pad(profile, 16)
		return AESInECBModeEncrypt(profile, key)
	}
	isAdmin := func(profile []byte) bool {
		decodedProfile := AESInECBModeDecrypt(profile, key)
		pairs := strings.Split(string(decodedProfile), "&")
		for _, p := range pairs {
			k := strings.Split(p, "=")
			if k[0] == "role" && k[1] == "admin" {
				return true
			}
		}
		return false
	}
	return encrypt, isAdmin
}

func createAdminProfile() bool {
	encrypt, isAdmin := initProfileEncryption()
	p := profileFor("aaaaaaaaaaaaa")
	a := encrypt([]byte(p))
	firstTwoBlocks := a[:32]
	adminBlock := encrypt([]byte(profileFor("aaaaaaaaaaadmin")))[16:32]
	payload := append(firstTwoBlocks, adminBlock...)
	return isAdmin(payload)
}


func ECBWithUnknownSuffixAndPrefix() func([]byte) []byte {
	b64Plaintext := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
		"YnkK"
	unknown, err := base64.StdEncoding.DecodeString(b64Plaintext)
	if err != nil {
		panic("base64 decode failed")
	}

	prefixLength := GetRandomInt(100) + 32
	prefix := Key(prefixLength)
	key := Key(16)

	return func(pt []byte) []byte {
		pt = append(pt, []byte(unknown)...)
		pt = append(prefix, pt...)
		pt = Pad(pt, 16)
		return AESInECBModeEncrypt(pt, key)
	}
}


//admittedly, this function is a bit messy...
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

	offset := make([]byte, offsetLength)

	ct = encrypter(make([]byte, blockSize*2+offsetLength))
	blocks := BreakIntoBlocks(ct, blockSize)
	ourStart := 0
	for i := 0; i < len(blocks)-1; i++ {
		if reflect.DeepEqual(blocks[i], blocks[i+1]) {
			ourStart = i * 16
			break
		}
	}

	paddingLength -= offsetLength

	//Recover the plaintext
	payload = make([]byte, 16, 16)
	pt := []byte{}
	ctLength := len(encrypter([]byte("")))

	for blockStart := ourStart; blockStart < ctLength; blockStart += blockSize {
		blockEnd := blockStart + blockSize
		isLastBlock := blockEnd == ctLength
		ptBlock := []byte("")

		/* get plaintext for each block */
		for i := blockStart; i < blockEnd; i++ {
			payload = payload[1:]

			/* deal with dynamic padding values for the last block */
			if isLastBlock && len(ptBlock)+paddingLength > 16 {
				paddingVal := len(ptBlock) + paddingLength - 15
				for i := len(ptBlock) - 1; i > len(ptBlock)-paddingVal; i-- {
					ptBlock[i] = byte(paddingVal)
				}
			}

			/* build block map */
			blockMap := make(map[string]string)
			for i := 0; i < 256; i++ {

				fullBlock := append(payload, ptBlock...)
				fullBlock = append(fullBlock, byte(i))

				encryptedBlock := string(encrypter(append(offset, fullBlock...))[ourStart : ourStart+blockSize])
				blockMap[encryptedBlock] = string(fullBlock)
			}

			payloadEncrypted := encrypter(append(offset, payload...))[blockStart:blockEnd]
			foundPlaintext := blockMap[string(payloadEncrypted)]
			lastByte := foundPlaintext[15]
			ptBlock = append(ptBlock, lastByte)
		}

		payload = ptBlock
		pt = append(pt, ptBlock...)
	}

	return pt
}

//StripPadding calculates and removes PKCS#7 padding,
//and either returning the input without padding, or returning
//an error if there is no valid padding.
func StripPadding(b []byte) ([]byte, error) {
	length := len(b)
	lastByte := b[length-1]
	paddingLen := int(lastByte)
	if paddingLen > length || paddingLen == 0 {
		return nil, errors.New("invalid padding!")
	}
	for i := 0; i < paddingLen; i++ {
		index := length - i - 1
		if b[index] != lastByte {
			return nil, errors.New("invalid padding!")
		}
	}
	return b[:length-paddingLen], nil
}

func initCommentEncryption() (func([]byte) []byte, func([]byte) bool) {
	adminString := ";admin=true;"

	key := Key(16)
	iv := Key(16)

	encryptComment := func(comment []byte) []byte {
		prependText := []byte("comment1=cooking%20MCs;userdata=")
		appendText := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
		for i := 0; i < len(comment); i++ {
			if comment[i] == ';' || comment[i] == '=' {
				ch := comment[i]
				replacedText := []byte{'"', ch, '"'}

				before := make([]byte, len(comment[:i]))
				after := make([]byte, len(comment[i+1:]))

				copy(before, comment[:i])
				copy(after, comment[i+1:])

				comment = append(before, replacedText...)
				comment = append(comment, after...)

				i += 2
			}
		}
		comment = append(comment, appendText...)
		comment = append(prependText, comment...)
		comment = Pad(comment, 16)
		return AESInCBCModeEncrypt(comment, key, iv)
	}
	decryptAndCheckAdmin := func(ct []byte) bool {
		pt := AESInCBCModeDecrypt(ct, key, iv)
		if strings.Contains(string(pt), adminString) {
			return true
		}
		return false
	}
	return encryptComment, decryptAndCheckAdmin
}

func createBitflippedAdmin() bool {
	encryptComment, checkAdmin := initCommentEncryption()
	payload := []byte(":admin<true")
	ct := encryptComment(payload)
	//flip some bits - changes ':' and '<' characters to ';' and '='
	//in the plaintext
	ct[16] ^= 1
	ct[22] ^= 1

	return checkAdmin(ct)
}
