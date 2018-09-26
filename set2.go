package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"log"
	"math/rand"
	"strings"
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

	unknownPt := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgYnkK" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unknownPtDecoded, _ := base64.StdEncoding.DecodeString(unknownPt)

	key := make([]byte, 16)
	rand.Read(key)

	return func(pt []byte) []byte {
		pt = append(pt, []byte(unknownPtDecoded)...)
		pt = Pad(pt, 16)
		return AESInECBModeEncrypt(pt, key)
	}
}

func AttackECBSuffix() []byte {
	encrypter := ECBWithUnknownSuffix()
	//Discover the block size of the cipher.
	var payload []byte
	prev := len(encrypter(payload))
	current := prev
	for prev == current {
		payload = append(payload, byte('A'))
		prev = current
		current = len(encrypter(payload))
	}
	blockSize := current - prev

	//Detect that the function is using ECB
	payload = make([]byte, blockSize*2, blockSize*2)
	ct := encrypter(payload)
	if !AESInECBModeOracle(ct) {
		panic("ECB mode not detected")
	}

	//Recover the plaintext
	prevPlaintext := []byte("AAAAAAAAAAAAAAAAA")
	textLen := len(encrypter([]byte(""))) / 16
	out := []byte{}
	for i := 0; i < textLen; i++ {
		prevPlaintext = recoverIndividualBlock(i, 16, prevPlaintext, encrypter)
		out = append(out, prevPlaintext...)
	}

	return out
}

func recoverIndividualBlock(blockNumber, blockLen int,
	prevBlockPlaintext []byte, encrypter func([]byte) []byte) []byte {

	padding := 1

	bs := blockNumber * blockLen
	be := bs + blockLen
	blockStart := prevBlockPlaintext[1:16]
	foundPlaintext := []byte("")
	for i := bs; i < be; i++ {
		blockMap := make(map[string]string)
		for i := 0; i < 256; i++ {
			endChar := byte(i)
			block := append(blockStart, foundPlaintext...)
			block = append(block, endChar)
			encryptedBlock := string(encrypter(block)[0:blockLen])
			blockMap[encryptedBlock] = string(block)
		}
		oneShort := encrypter(blockStart)
		blockPlaintext := []byte(blockMap[string(oneShort[bs:be])])
		if len(blockPlaintext) == 0 {
			panic("length is zero...")
		}
		foundPlaintext = blockPlaintext[0+len(blockStart) : 16]

		if len(oneShort) == be {
			l := len(foundPlaintext)
			if foundPlaintext[l-1] == byte(padding) {
				padding += 1
				for j := l - 1; j > l-padding; j-- {
					foundPlaintext[j] = byte(padding)
				}
			}
		}

		if len(blockStart) > 0 {
			blockStart = blockStart[1:]
		}
	}
	return foundPlaintext
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

func ECBWithUnknownSuffixandPrefix() func([]byte) []byte {
	unknownPt := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgYnkK" +
		"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
		"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
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

//needs a bit more work
/*func AttackECBSuffixAndPrefix() []byte{
	encrypter := ECBWithUnknownSuffixandPrefix()
	//Discover the block size of the cipher.
	var payload []byte
	prev := len(encrypter(payload))
	current := prev
	for prev == current {
		payload = append(payload, byte('A'))
		prev = current
		current = len(encrypter(payload))
	}
	blockSize := current - prev

	//Detect that the function is using ECB
	payload = make([]byte, blockSize * 3, blockSize * 3)
	ct := encrypter(payload)
	if !AESInECBModeOracle(ct) {
		panic("ECB mode not detected")
	}

	blocks := BreakIntoBlocks(ct, blockSize)
	previous := []byte{}
	startBlock := 0

	for i := 0; i < len(blocks); i++ {
		if string(previous) == string(blocks[i]) {
			startBlock = i
			break
		}
		previous = blocks[i]
	}

	//Recover the plaintext
	prevPlaintext := []byte("AAAAAAAAAAAAAAAAA")
	textLen := len(encrypter([]byte(""))) / 16
	out := []byte{}
	for i:=startBlock; i < textLen; i++ {

		prevPlaintext = recoverIndividualBlock2(i, 16, prevPlaintext,
		encrypter, startBlock)

		out = append(out, prevPlaintext...)
	}

	return out
}

func recoverIndividualBlock2(blockNumber, blockLen int,
	prevBlockPlaintext []byte, encrypter func([]byte) []byte, start int) []byte {

	padding := 1

	bs := blockNumber * blockLen
	be := bs + blockLen
	blockStart := prevBlockPlaintext[1:16]
	foundPlaintext := []byte("")
	for i:=bs; i<be; i++ {
		blockMap := make(map[string]string)
		for i := 0; i < 256; i++ {
			endChar := byte(i)
			block := append(blockStart, foundPlaintext...)
			block = append(block, endChar)
			encryptedBlock := string(encrypter(block)[start * 16:start * 16 + 16])
			blockMap[encryptedBlock] = string(block)
		}
		oneShort := encrypter(blockStart)
		blockPlaintext := []byte(blockMap[string(oneShort[bs:be])])
		if len(blockPlaintext) == 0 {
			panic("length is zero...")
		}
		foundPlaintext = blockPlaintext[0 + len(blockStart):16]

			if len(oneShort) == be {
				l := len(foundPlaintext)
				if foundPlaintext[l - 1] == byte(padding) {
					log.Println("here")
					padding += 1
					for j:= l - 1; j > l - padding; j-- {
						foundPlaintext[j] = byte(padding)
					}
				}
			}

		if len(blockStart) > 0 {
			blockStart = blockStart[1:]
		}
	}
	return foundPlaintext
}

*/
