package cryptopals

import (
	"fmt"
	"log"
	"strconv"
	"strings"
)

/*
Recover the key from CBC with IV=Key

Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.

Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know the key already, and can save some space by using it as both a key and an IV.

Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get the receiver to decrypt a value that will reveal the key.

The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).

Use your code to encrypt a message that is at least 3 blocks long:

AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3

Modify the message (you are now the attacker):

C_1, C_2, C_3 -> C_1, 0, C_1

Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.

As the attacker, recovering the plaintext from the error, extract the key:

P'_1 XOR P'_3
*/

func initCommentEncryptionWithMatchingKeyAndIv() (func([]byte) []byte, func([]byte) (bool, error)) {
	adminString := ";admin=true;"

	key := Key(16)
	iv := key
	log.Println("key", key)
	encryptComment := func(comment []byte) []byte {
		prependText := []byte("comment1=cooking%20MCs;userdata=")
		appendText := []byte(";comment2=%20like%20a%20pound%20of%20bacon")
		for i := 0; i < len(comment); i++ {
			if comment[i] == ';' || comment[i] == '=' {
				ch := comment[i]
				replacedText := []byte{'"', ch, '"'}

				before := make([]byte, len(comment[:i]))
				after := make([]byte, len(comment[i+1:]))

				copy(before, comment[:i])
				copy(after, comment[i+1:])

				comment = append(before, replacedText...)
				comment = append(comment, after...)

				i += 2
			}
		}
		comment = append(comment, appendText...)
		comment = append(prependText, comment...)
		comment = Pad(comment, 16)
		return AESInCBCModeEncrypt(comment, key, iv)
	}
	decryptAndCheckAdmin := func(ct []byte) (bool, error) {
		pt := AESInCBCModeDecrypt(ct, key, iv)
		for _, b := range pt {
			if b&0x8 > 0 {
				return false, fmt.Errorf("non-ASCII characters found: %v", pt)
			}
		}
		if strings.Contains(string(pt), adminString) {
			return true, nil
		}
		return false, nil
	}
	return encryptComment, decryptAndCheckAdmin
}

func findCBCKey() []byte {
	encryptComment, checkAdmin := initCommentEncryptionWithMatchingKeyAndIv()
	ct := encryptComment([]byte{})
	firstBlock := ct[:16]
	newCt := append(firstBlock, make([]byte, 16)...)
	newCt = append(newCt, firstBlock...)

	_, err := checkAdmin(ct)
	if err != nil {
		e := err.Error()
		start := strings.Index(e, "[")
		end := strings.Index(e, "]")
		e = e[start+1 : end]
		stringBytes := strings.Split(e, " ")
		var pt []byte
		for _, s := range stringBytes {
			i, _ := strconv.Atoi(s)
			pt = append(pt, byte(i))
		}
		return XOr(pt[0:16], pt[32:48])
	}
	log.Fatal("Attack didn't work")
	return []byte{}
}
