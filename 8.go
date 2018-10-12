package cryptopals

/*
Detect AES in ECB mode

In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
*/

/*
AESInECBMode checks if there are duplicate 16-byte blocks
in the ciphertext, andc returns true if it finds any.
Otherwise, the function returns false.
*/
func AESInECBModeOracle(ct []byte) bool {
	blockMap := make(map[string]bool)
	blocks := BreakIntoBlocks(ct, 16)
	for _, block := range blocks {
		strBlock := string(block)
		if blockMap[strBlock] {
			return true
		}
		blockMap[strBlock] = true
	}
	return false
}
