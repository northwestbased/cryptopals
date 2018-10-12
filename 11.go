package cryptopals

import (
	"crypto/aes"
	"log"
)

/*
An ECB/CBC detection oracle

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
*/

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
