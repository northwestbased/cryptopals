package cryptopals

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"math"
	"unicode"
)

func HexToBase64(hexStr string) (string, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}

func XOr(b1, b2 []byte) []byte {
	if len(b1) != len(b2) {
		panic("buffers are not the same length")
	}

	out := make([]byte, len(b1))
	for i := 0; i < len(b1); i++ {
		out[i] = b1[i] ^ b2[i]
	}
	return out
}

/*
Single Byte XOr Cypher
Each byte in the plaintext is XOr'd against a single character.
Encryption is identical to decryption.
This is just a special case of ReapeatingKeyXOr
*/
func SingleByteXOrCipher(text []byte, key byte) []byte {
	return RepeatingKeyXOrCipher(text, []byte{key})
}

func RepeatingKeyXOrCipher(text, key []byte) []byte {
	output := make([]byte, len(text))
	for i, b := range text {
		output[i] = b ^ key[i%len(key)]
	}
	return output
}

/*
BreakSingleByteXOrCipher Uses English letter frequencies to find the most
likely key for a given ciphertext, presuming that the ciphertext was
encrypted using the Single Byte XOr Cypher. This function returns a
the key, plaintext, and the difference between the average letter
distribution for English and the plaintext.
*/
func BreakSingleByteXOrCipher(ciphertext []byte) (byte, []byte, float64) {
	//English letter frequency, including the space character
	englishFrequency := map[byte]float64{
		' ': 0.182884,
		'E': 0.102666,
		'T': 0.075169,
		'A': 0.065321,
		'O': 0.061595,
		'N': 0.057120,
		'I': 0.056684,
		'S': 0.053170,
		'R': 0.049879,
		'H': 0.049785,
		'L': 0.033175,
		'D': 0.032829,
		'U': 0.022757,
		'C': 0.022336,
		'M': 0.020265,
		'F': 0.019830,
		'W': 0.017038,
		'G': 0.016249,
		'P': 0.015043,
		'Y': 0.014276,
		'B': 0.012588,
		'V': 0.007961,
		'K': 0.005609,
		'X': 0.001409,
		'J': 0.000975,
		'Q': 0.000836,
		'Z': 0.000512,
	}
	var key byte
	var plaintext []byte
	smallestDif := math.MaxFloat64

	//guess different byte values for the key
	for k := 0; k < 256; k++ {
		pt := SingleByteXOrCipher(ciphertext, byte(k))
		ctFrequency := make(map[byte]float64)
		//map each byte in the decrypted plaintext to it's frequency
		for _, letter := range pt {
			letter := byte(unicode.ToUpper(rune(letter)))
			ctFrequency[letter] += 1 / float64(len(ciphertext))
		}

		//compare the frequency of letters in English to the calculated frequency
		//for our plaintext. the key with the smallest difference is
		//most likely correct.
		var freqDif float64
		for letter, frequency := range ctFrequency {
			freqDif += math.Abs(englishFrequency[letter] - frequency)
		}
		if freqDif < smallestDif {
			smallestDif = freqDif
			plaintext = pt
			key = byte(k)
		}
	}
	return key, plaintext, smallestDif
}

func SingleByteXOrOracle(ct []byte) bool {
	_, _, difference := BreakSingleByteXOrCipher(ct)
	// The .5 here is a magic value. Any value much larger than
	// this is too far away from the average distribution to be
	// interpreted as English
	if difference < .5 {
		return true
	}
	return false
}

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

func AESInECBModeDecrypt(ct, key []byte) []byte {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	bs := cipher.BlockSize() //Blocksize() should always return 16
	if len(ct)%bs != 0 {
		panic("Ciphertext length needs to be a multiple of the blocksize")
	}
	dst := make([]byte, bs)
	var out []byte

	for i := 0; i < len(ct); i += bs {
		cipher.Decrypt(dst, ct[i:i+bs])
		out = append(out, dst[:]...)
	}

	return out
}

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
