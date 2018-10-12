package cryptopals

import "math"

/*
Break repeating-key XOR

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

    Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

    this is a test

    and

    wokka wokka!!!

    is 37. Make sure your code agrees before you proceed.
    For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    Solve each block as if it was single-character XOR. You already have code to do this.
    For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.
*/

func HammingDistance(b1, b2 []byte) int {
	hd := 0
	for i := 0; i < len(b1); i++ {
		xor := int(b1[i] ^ b2[i])
		for xor > 0 {
			hd += xor & 1
			xor = xor >> 1
		}
	}
	return hd
}

func FindBestXOrKeyLength(ct []byte) int {
	smallestHd := math.MaxFloat64
	var keySize int
	for i := 2; i < 41; i++ {
		hd := float64(HammingDistance(ct[:i*4], ct[i*4:i*8])) / float64(i)
		if hd < smallestHd {
			smallestHd = hd
			keySize = i
		}
	}
	return keySize
}

func BreakRepeatingKeyXOrCipher(ct []byte) []byte {
	keySize := FindBestXOrKeyLength(ct)
	var ctBlocks [][]byte
	//break the ciphertext into blocks of KEYSIZE length
	//the last block may be shorter if ct % keySize != 0
	for i := 0; i < len(ct)-keySize; i += keySize {
		endIndex := i + keySize
		if endIndex > len(ct) {
			endIndex = len(ct)
		}
		ctBlocks = append(ctBlocks, ct[i:endIndex])
	}
	//Now transpose the blocks: make a block that is the first byte of every
	//block, and a block that is the second byte of every block, and so on.
	var singleByteXOrBlocks [][]byte
	for i := 0; i < keySize; i++ {
		var newBlock []byte
		for _, block := range ctBlocks {
			if i < len(block) {
				newBlock = append(newBlock, block[i])
			}
		}
		singleByteXOrBlocks = append(singleByteXOrBlocks, newBlock)
	}
	//Solve each block as if it was single-character XOR
	var key []byte
	for _, block := range singleByteXOrBlocks {
		newChar, _, _ := BreakSingleByteXOrCipher(block)
		key = append(key, newChar)
	}
	return key

}
