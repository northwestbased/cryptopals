package cryptopals

import "crypto/aes"

/*
AES in ECB mode

The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".

(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
Do this with code.

You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.
*/

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
