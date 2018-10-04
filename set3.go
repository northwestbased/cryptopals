package cryptopals

import (
	"encoding/base64"
	"encoding/binary"
	"log"
)

func GetRandomString() []byte {
	plaintexts := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	index := GetRandomInt(len(plaintexts))
	decoded, err := base64.StdEncoding.DecodeString(plaintexts[index])
	if err != nil {
		panic(err)
	}
	return decoded
}

func CBCServerMockup() (ct, iv []byte, checkPadding func([]byte) bool) {
	pt := []byte(GetRandomString())
	pt = Pad(pt, 16)

	key := Key(16)

	//values we are returning:
	iv = Key(16)
	ct = AESInCBCModeEncrypt(pt, key, iv)
	checkPadding = func(ct []byte) bool {
		pt := AESInCBCModeDecrypt(ct, key, iv)
		_, err := StripPadding(pt)
		if err != nil {
			return false
		}
		return true
	}

	return
}

func CBCPaddingOracle() []byte {
	var out []byte
	ct, iv, decrypt := CBCServerMockup()
	blocks := BreakIntoBlocks(ct, 16)
	iv2 := [][]byte{iv}
	blocks = append(iv2, blocks...)
	for b := 1; b < len(blocks); b++ {
		target := blocks[b]
		prev := make([]byte, 16)
		copy(prev, blocks[b-1])

		//find initial padding for block
		initialPadding := 0

		if decrypt(append(prev, target...)) {
			prevCopy := make([]byte, 16)
			copy(prevCopy, prev)
			i := -1
			for decrypt(append(prevCopy, target...)) {
				i++
				prevCopy[i] ^= 0xFF
			}
			initialPadding = 16 - i
		}

		for padding := initialPadding; padding <= 15; padding++ {
			targetChar := 16 - padding - 1
			newPaddingVal := padding + 1
			for i := targetChar + 1; i < 16; i++ {
				prev[i] ^= byte(padding) ^ byte(newPaddingVal)
			}

			i := 0
			for i = 0; i < 256; i++ {
				prev[targetChar] = byte(i)
				if decrypt(append(prev, target...)) {
					break
				}

			}
		}
		v := XOr(prev, blocks[b-1])
		out = append(out, SingleByteXOrCipher(v, 16)...)
	}
	return out
}

func CTR_Cipher(text, key, nonce []byte) []byte {
	var counter uint64
	bs := make([]byte, 8)
	var output []byte

	for i := 0; i < len(text); i += 16 {
		binary.LittleEndian.PutUint64(bs, counter)

		blockStart := i
		blockEnd := i + 16
		blockLength := 16

		if blockEnd >= len(text) {
			blockEnd = len(text)
			blockLength = blockEnd - blockStart
		}

		block := text[blockStart:blockEnd]

		//use AESInECBMode function. Encrypting one block in ECB is the same as
		//calling the AES cipher directly, but by calling AESInECBMode we don't
		//have to write the extra code :)
		stream := AESInECBModeEncrypt(append(nonce, bs...), key)
		newBlock := XOr(block, stream[:blockLength])
		output = append(output, newBlock...)
		counter++
	}
	return output
}

func BreakCTRManually() {
	nonce := Key(8)
	key := Key(16)

	lines, err := ReadFileByLine("input/19.txt")
	if err != nil {
		panic(err)
	}
	var ciphertexts [][]byte
	for _, line := range lines {
		plaintext, _ := base64.StdEncoding.DecodeString(line)
		ciphertext := CTR_Cipher(plaintext, key, nonce)
		ciphertexts = append(ciphertexts, ciphertext)
	}

	input, err := ReadFileByLine("input/19_guesses.txt")
	if err != nil {
		return
	}
	first := []byte(input[0])

	var ciphertext []byte
	for _, ct := range ciphertexts {
		if len(ct) > len(ciphertext) {
			ciphertext = ct
		}
	}

	var guessedKey []byte

	for index, letter := range first {
		ciphertextByte := ciphertext[index]
		keyByte := ciphertextByte ^ byte(letter)
		guessedKey = append(guessedKey, keyByte)
	}
	for _, ct := range ciphertexts {
		longest := len(ct)
		if len(guessedKey) < longest {
			longest = len(guessedKey)
		}
		log.Println(string(XOr(guessedKey[:longest], ct[:longest])))
	}
}

func BreakCTRStatistically() {
	nonce := Key(8)
	key := Key(16)

	lines, _ := ReadFileByLine("input/19.txt")
	minLength := -1
	for _, line := range lines {
		l, _ := base64.StdEncoding.DecodeString(line)

		if len(l) < minLength || minLength == -1 {
			minLength = len(l)
		}
	}

	var ciphertext []byte
	for _, line := range lines {
		l, _ := base64.StdEncoding.DecodeString(line)

		l = CTR_Cipher(l, key, nonce)
		ciphertext = append(ciphertext, l[:minLength]...)
	}
	key = BreakRepeatingKeyXOrCipher(ciphertext)
	blocks := BreakIntoBlocks(RepeatingKeyXOrCipher(ciphertext, key), minLength)
	for _, b := range blocks {
		log.Println(string(b))
	}
}
