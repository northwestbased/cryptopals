package cryptopals

/*
Detect single-character XOR

One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)
*/

func SingleByteXOrOracle(ct []byte) bool {
	_, _, difference := BreakSingleByteXOrCipher(ct)
	// The .8 here is a magic value. Any value much larger than
	// this is too far away from the average distribution to be
	// interpreted as English
	if difference < .8 {
		return true
	}
	return false
}
