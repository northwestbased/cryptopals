package cryptopals

import "crypto/aes"

/*
Implement CBC mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
*/

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
