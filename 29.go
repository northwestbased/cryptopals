package cryptopals

import (
	"bytes"
	"encoding/binary"
	"log"
	"strings"
)

/*
Break a SHA-1 keyed MAC using length extension

Secret-prefix SHA-1 MACs are trivially breakable.

The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".

Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.

To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding. We call this "glue padding". The final message you actually forge will be:

SHA1(key || original-message || glue-padding || new-message)

(where the final padding on the whole constructed message is implied)

Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.

This sounds more complicated than it is in practice.

To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using. This should take you 5-10 minutes.

Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).

Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c (they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.

Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from /usr/share/dict/words or something) of the string:

"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

Forge a variant of this message that ends with ";admin=true".
*/

func SHA1SetInitialState(text []byte, state []uint32) []byte {

	SHA1Block(state, text)

	digest := make([]byte, 20)

	putUint32(digest[0:], state[0])
	putUint32(digest[4:], state[1])
	putUint32(digest[8:], state[2])
	putUint32(digest[12:], state[3])
	putUint32(digest[16:], state[4])
	return digest
}

func CheckValidMacUnderKeyFactory() (func([]byte) []byte, func([]byte, []byte) bool) {
	keyLen := GetRandomInt(20) + 5
	key := Key(keyLen)

	checkIfAdmin := func(str []byte, hash []byte) bool {
		if bytes.Equal(KeyedSHA1(key, str), hash) && strings.Contains(string(str), ";admin=true") {
			return true
		} else {
			return false
		}
	}
	createHash := func(b []byte) []byte {
		if strings.Contains(string(b), "admin=true") {
			panic("Someone is attacking!")
		}
		return KeyedSHA1(key, b)
	}
	return createHash, checkIfAdmin
}

func LengthExtendSha1() {
	val := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	postText := []byte(";admin=true")
	hash, checkHash := CheckValidMacUnderKeyFactory()
	hashSum := hash(val)

	s0 := binary.BigEndian.Uint32(hashSum[0:4])
	s1 := binary.BigEndian.Uint32(hashSum[4:8])
	s2 := binary.BigEndian.Uint32(hashSum[8:12])
	s3 := binary.BigEndian.Uint32(hashSum[12:16])
	s4 := binary.BigEndian.Uint32(hashSum[16:20])
	for i := 0; i < 100; i++ {
		keyLen := i
		initialPadding := PadSHA(keyLen + len(val))

		newPadding := PadSHA(keyLen + len(val) + len(postText) + len(initialPadding))
		sneakyHash := SHA1SetInitialState(append(postText, newPadding...), []uint32{s0, s1, s2, s3, s4})

		fullText := append(val, initialPadding...)
		fullText = append(fullText, postText...)
		log.Println(checkHash(fullText, sneakyHash))
	}
}
