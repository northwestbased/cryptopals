package cryptopals

import (
	"encoding/base64"
	"log"
)

/*
Break fixed-nonce CTR statistically

In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.

Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.
*/

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
