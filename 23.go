package cryptopals

/*
Clone an MT19937 RNG from its output

The internal state of MT19937 consists of 624 32 bit integers.

For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a period of 2**19937, which is Big.

Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.

The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order. There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number. So you'll need code to invert the "right" and the "left" operation.

Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.

The new "spliced" generator should predict the values of the original.
*/

func CloneMTwisterState(state []uint32) []uint32 {
	reverseRightShift := func(product uint32, offset uint) uint32 {
		mask := uint32(0xFFFFFFFF << (32 - offset))
		y := product & mask

		for i := 32 - offset; i >= 0 && i < 33; i-- {
			mask = 1 << i
			pbit := product & mask
			ybit := (y >> offset) & mask
			y |= pbit ^ ybit
		}
		return y

	}

	reverseLeftShift := func(product uint32, offset uint, and uint32) uint32 {
		mask := uint32(0xFFFFFFFF >> (32 - offset))
		y := product & mask
		for i := offset; i < 32; i++ {
			mask = 1 << i
			pbit := product & mask
			ybit := (y << offset) & mask
			andBit := and & mask
			y |= pbit ^ ybit&andBit
		}
		return y
	}

	for i, s := range state {
		s = reverseRightShift(s, 18)
		s = reverseLeftShift(s, 15, 0xefc60000)
		s = reverseLeftShift(s, 7, 0x9d2c5680)
		state[i] = reverseRightShift(s, 11)
	}
	return state
}
