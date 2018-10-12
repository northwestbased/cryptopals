package cryptopals

import "strings"

/*
CBC bitflipping attacks

Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="

.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

    Completely scrambles the block the error occurs in
    Produces the identical 1-bit error(/edit) in the next ciphertext block.
*/

func initCommentEncryption() (func([]byte) []byte, func([]byte) bool) {
	adminString := ";admin=true;"

	key := Key(16)
	iv := Key(16)

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
	decryptAndCheckAdmin := func(ct []byte) bool {
		pt := AESInCBCModeDecrypt(ct, key, iv)
		if strings.Contains(string(pt), adminString) {
			return true
		}
		return false
	}
	return encryptComment, decryptAndCheckAdmin
}

func createBitflippedAdmin() bool {
	encryptComment, checkAdmin := initCommentEncryption()
	payload := []byte(":admin<true")
	ct := encryptComment(payload)
	//flip some bits - changes ':' and '<' characters to ';' and '='
	//in the plaintext
	ct[16] ^= 1
	ct[22] ^= 1

	return checkAdmin(ct)
}
