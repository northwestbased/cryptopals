package cryptopals

import "encoding/binary"

/*
Implement CTR, the stream cipher mode

The string:

L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==

... decrypts to something approximating English in CTR mode, which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:

      key=YELLOW SUBMARINE
      nonce=0
      format=64 bit unsigned little endian nonce,
             64 bit little endian block count (byte count / 16)

CTR mode is very simple.

Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream, which is XOR'd against the plaintext.

For instance, for the first 16 bytes of a message with these parameters:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

... for the next 16 bytes:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")

... and then:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and stop generating keystream.

Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.

Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.
*/

func CTR_Cipher(text, key, nonce []byte) []byte {
	var counter uint64
	bs := make([]byte, 8)
	var output []byte

	for i := 0; i < len(text); i += 16 {
		binary.LittleEndian.PutUint64(bs, counter)

		blockStart := i
		blockEnd := i + 16
		blockLength := 16

		if blockEnd >= len(text) {
			blockEnd = len(text)
			blockLength = blockEnd - blockStart
		}

		block := text[blockStart:blockEnd]

		//use AESInECBMode function. Encrypting one block in ECB is the same as
		//calling the AES cipher directly, but by calling AESInECBMode we don't
		//have to write the extra code :)
		stream := AESInECBModeEncrypt(append(nonce, bs...), key)
		newBlock := XOr(block, stream[:blockLength])
		output = append(output, newBlock...)
		counter++
	}
	return output
}
