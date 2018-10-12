package cryptopals

/*
Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965

... should produce:

746865206b696420646f6e277420706c6179
*/

//XOr xor's two equal length byte slices, and panics if the input slices aren't the same length
func XOr(b1, b2 []byte) []byte {
	if len(b1) != len(b2) {
		panic("buffers are not the same length")
	}

	out := make([]byte, len(b1))
	for i := 0; i < len(b1); i++ {
		out[i] = b1[i] ^ b2[i]
	}
	return out
}
