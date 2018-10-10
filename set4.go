package cryptopals

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"./sha1"
)

func CTRRandomAccessReadWrite(plaintext []byte) ([]byte, func([]byte, int, []byte) []byte) {
	nonce := Key(8)
	key := Key(16)
	ciphertext := CTR_Cipher(plaintext, key, nonce)

	updatePlaintext := func(ct []byte, offset int, newtext []byte) []byte {
		pt := CTR_Cipher(ct, key, nonce)
		for i, b := range newtext {
			index := i + offset
			if index > len(pt) {
				break
			}
			pt[index] = b
		}
		return CTR_Cipher(pt, key, nonce)
	}
	return ciphertext, updatePlaintext
}

func BreakCTRRandomAccess(ciphertext []byte, updatePlaintext func([]byte, int, []byte) []byte) []byte {
	var out []byte
	for index := range ciphertext {
		log.Println(index)
		for i := 0; i < 256; i++ {
			payload := byte(i)
			newCiphertext := updatePlaintext(ciphertext, index, []byte{payload})
			if newCiphertext[index] == ciphertext[index] {
				out = append(out, payload)
				break
			}
		}
	}
	return out
}

func initCommentEncryptionCTR() (func([]byte) []byte, func([]byte) bool) {
	adminString := ";admin=true;"

	key := Key(16)
	nonce := Key(8)

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
		return CTR_Cipher(comment, key, nonce)

	}
	decryptAndCheckAdmin := func(ct []byte) bool {
		pt := CTR_Cipher(ct, key, nonce)
		if strings.Contains(string(pt), adminString) {
			return true
		}
		return false
	}
	return encryptComment, decryptAndCheckAdmin
}

func createBitflippedAdminCTR() bool {
	encryptComment, checkAdmin := initCommentEncryptionCTR()
	payload := []byte(":admin<true")
	ct := encryptComment(payload)
	//flip some bits - changes ':' and '<' characters to ';' and '='
	//in the plaintext
	ct[32] ^= 1
	ct[38] ^= 1

	return checkAdmin(ct)
}

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
	} else {
		log.Fatal("Attack didn't work")
	}
	return []byte{}
}

func SHA1(text, key []byte) []byte {
	h := sha1.New()
	h.Write([]byte(append(key, text...)))
	return h.Sum(nil)
}
