package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
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

func XOrBuffers(b1, b2 []byte) ([]byte, error) {
	if len(b1) != len(b2) {
		return []byte{}, errors.New("buffers are not the same length")
	}

	output := make([]byte, len(b1), len(b1))
	for i := 0; i < len(b1); i++ {
		output[i] = b1[i] ^ b2[i]
	}
	return output, nil
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
	output := make([]byte, len(text), len(text))
	for i, b := range text {
		output[i] = b ^ key[i%len(key)]
	}
	return output
}

/*
	BreakSingleByteXOr Uses English letter frequencies to find the most
	likely key for a given ciphertext, presuming that the ciphertext was
	encrypted using the Single Byte XOr Cypher. This function returns a
	the key, plaintext, and the difference between the average letter
	distribution for English and the plaintext.
*/
func BreakSingleByteXOr(ct []byte) (byte, []byte, float64) {
	letterFrequency := map[byte]float64{
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
	lowest := math.MaxFloat64
	plaintext := []byte{}
	var outKey byte

	for key := 0; key < 256; key++ {
		pt := SingleByteXOrCipher(ct, byte(key))
		newFreq := make(map[byte]float64)
		otherCharacters := 0

		for _, letter := range pt {
			letter := byte(unicode.ToUpper(rune(letter)))
			if letterFrequency[letter] > 0 {
				newFreq[letter] = 1 / float64(len(ct))
			} else {
				otherCharacters += 1
			}
		}
		var difference float64
		for k, _ := range letterFrequency {
			difference += math.Abs(letterFrequency[k] - newFreq[k])
		}
		difference += float64(otherCharacters) / float64(len(ct))
		if difference < lowest {
			lowest = difference
			plaintext = pt
			outKey = byte(key)
		}
	}
	return outKey, plaintext, lowest
}

func SingleByteXOrOracle(ct []byte) bool {
	_, _, difference := BreakSingleByteXOr(ct)
	// The .8 here is a magic value. Any value much larger than
	// this is too far away from the average distribution to be
	// interpreted as English
	if difference > .8 {
		return false
	}
	return true
}

func HammingDistance(b1, b2 []byte) int {
	hd := 0
	for i := 0; i < len(b1); i++ {
		xor := int(b1[i] ^ b2[i])
		for xor > 0 {
			hd += xor % 2
			xor = xor / 2
		}
	}
	return hd
}

func FindBestKeyLength(ct []byte) int {
	smallestHd := math.MaxFloat64
	var keyLen int
	for i := 2; i < 41; i++ {
		hd := float64(HammingDistance(ct[:i * 6], ct[i * 6:i * 12])) / float64(i)
		if hd < smallestHd {
			smallestHd = hd
			keyLen = i
		}
	}
	return keyLen
}



func BreakRepeatingKeyXOrCipher(ct []byte) []byte{
	keyLen := FindBestKeyLength(ct)
	var ctBlocks [][]byte
	//break the ciphertext into blocks of KEYSIZE length
	for i := 0; i < len(ct) - keyLen; i += keyLen {
		endIndex := i + keyLen
		if endIndex > len(ct) {
			endIndex = len(ct)
		}
		ctBlocks = append(ctBlocks, ct[i:endIndex])
	}
	//Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
	var singleByteXOrBlocks [][]byte
	for i := 0; i < keyLen; i++ {
		var newBlock []byte
		for _, block := range ctBlocks {
			if i < len(block) {
				newBlock = append(newBlock, block[i])
			}
		}
		singleByteXOrBlocks = append(singleByteXOrBlocks, newBlock)
	}
	//Solve each block as if it was single-character XOR. You already have code to do this.
	var key []byte
	for _, block := range singleByteXOrBlocks {
		newChar, _, _ := BreakSingleByteXOr(block)
		key = append(key, newChar)
	}
	return key

}
