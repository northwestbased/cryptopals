package cryptopals

import "log"

/*
Break "random access read/write" AES CTR

Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).

Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".

Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.
*/

func CTRRandomAccessReadWrite(plaintext []byte) ([]byte, func([]byte, int, []byte) []byte) {
	nonce := Key(8)
	key := Key(16)
	ciphertext := CTR_Cipher(plaintext, key, nonce)

	updatePlaintext := func(ct []byte, offset int, newtext []byte) []byte {
		pt := CTR_Cipher(ct, key, nonce)
		for i, b := range newtext {
			index := i + offset
			if index > len(pt) {
				break
			}
			pt[index] = b
		}
		return CTR_Cipher(pt, key, nonce)
	}
	return ciphertext, updatePlaintext
}

func BreakCTRRandomAccess(ciphertext []byte, updatePlaintext func([]byte, int, []byte) []byte) []byte {
	var out []byte
	for index := range ciphertext {
		log.Println(index)
		for i := 0; i < 256; i++ {
			payload := byte(i)
			newCiphertext := updatePlaintext(ciphertext, index, []byte{payload})
			if newCiphertext[index] == ciphertext[index] {
				out = append(out, payload)
				break
			}
		}
	}
	return out
}
