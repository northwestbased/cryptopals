package cryptopals

import "errors"

/*

PKCS#7 padding validation

Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"

... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"

... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
*/

//StripPadding calculates and removes PKCS#7 padding,
//and either returning the input without padding, or returning
//an error if there is no valid padding.
func StripPadding(b []byte) ([]byte, error) {
	length := len(b)
	lastByte := b[length-1]
	paddingLen := int(lastByte)
	if paddingLen > length || paddingLen == 0 {
		return nil, errors.New("invalid padding!")
	}
	for i := 0; i < paddingLen; i++ {
		index := length - i - 1
		if b[index] != lastByte {
			return nil, errors.New("invalid padding!")
		}
	}
	return b[:length-paddingLen], nil
}
