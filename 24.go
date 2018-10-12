package cryptopals

import (
	"log"
	"strconv"
	"strings"
	"time"
)

/*

Create the MT19937 stream cipher and break it

You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.

Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.

Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.

From the ciphertext, recover the "key" (the 16 bit seed).

Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.

Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
*/

func MT19937StreamCipher(text []byte, key uint16) []byte {
	var output []byte

	mt := MersenneTwister{}
	mt.init(uint32(key))
	var keyStreamBuffer []byte
	for _, t := range text {
		if len(keyStreamBuffer) == 0 {
			num := mt.ExtractNumber()
			str := strconv.Itoa(int(num))
			keyStreamBuffer = append(keyStreamBuffer, []byte(str)...)
		}
		output = append(output, t^keyStreamBuffer[0])
		keyStreamBuffer = keyStreamBuffer[1:]
	}
	return output
}

func MT19937StreamCipherEncryptWithPrefix(text []byte) []byte {
	key := uint16(GetRandomInt(0x10000))
	prefixLength := GetRandomInt(1000)
	prefix := Key(prefixLength)
	text = append(prefix, text...)
	return MT19937StreamCipher(text, key)
}

func BreakMTStreamCipherWithPrefix() {
	ct := MT19937StreamCipherEncryptWithPrefix([]byte("AAAAAAAAAAAAAAAAAAA"))
	for i := 0; i < 0x10000; i++ {
		key := uint16(i)
		out := MT19937StreamCipher(ct, key)
		if strings.Contains(string(out), "AAAAAAAAAAAAAAAAAAA") {
			log.Println("found it!", key, out)
		}
	}

}

func CreatePasswordResetToken() []byte {
	seed := uint32(time.Now().Unix())
	prefixLength := GetRandomInt(1000)
	prefix := Key(prefixLength)
	text := append(prefix, []byte("password reset")...)
	return MT19937StreamCipher(text, uint16(seed))
}

func CheckPasswordResetToken(ct []byte) bool {
	time := uint16(time.Now().Unix())
	for i := 0; i < 10; i++ {
		pt := MT19937StreamCipher(ct, uint16(time-uint16(i)))
		if strings.Contains(string(pt), "password reset") {
			return true
		}
	}
	return false
}
