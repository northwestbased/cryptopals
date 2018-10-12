package cryptopals

import "strings"

/*
CTR bitflipping

There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode. Inject an "admin=true" token.
*/

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
