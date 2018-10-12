package cryptopals

import "encoding/base64"

/*
The CBC padding oracle

This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.
*/

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
