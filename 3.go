package cryptopals

import (
	"math"
	"unicode"
)

/*
Single-byte XOR cipher

The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.
Achievement Unlocked

You now have our permission to make "ETAOIN SHRDLU" jokes on Twitter.
*/

/*
SingleByteXOrCipher encryptes a byte slice against a single-byte key. This is just a special case of ReapeatingKeyXOr that we will write for problem 5.
*/
func SingleByteXOrCipher(text []byte, key byte) []byte {
	return RepeatingKeyXOrCipher(text, []byte{key})
}

/*
BreakSingleByteXOrCipher Uses English letter frequencies to find the most
likely key for a given ciphertext, presuming that the ciphertext was
encrypted using the Single Byte XOr Cypher. This function returns a
the key, plaintext, and the difference between the average letter
distribution for English and the plaintext.
*/
func BreakSingleByteXOrCipher(ct []byte) (byte, []byte, float64) {
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
