package cryptopals

import (
	"encoding/base64"
	"reflect"
)

/*
Byte-at-a-time ECB decryption (Harder)

Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.
*/

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
