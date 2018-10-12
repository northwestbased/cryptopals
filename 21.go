package cryptopals

/*
Implement the MT19937 Mersenne Twister RNG

You can get the psuedocode for this from Wikipedia.

If you're writing in Python, Ruby, or (gah) PHP, your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.
*/

// based on pseudocode from https://en.wikipedia.org/w/index.php?title=Mersenne_Twister&oldid=408201780
type MersenneTwister struct {
	state []uint32
	index int
}

// Initialize the generator from a seed
func (mt *MersenneTwister) init(seed uint32) {
	mt.state = make([]uint32, 624)
	mt.state[0] = seed
	for i := 1; i < 624; i++ { // loop over each other element
		mt.state[i] = (1812433253 * (mt.state[i-1] ^ (mt.state[i-1] >> 30))) + uint32(i)
	}
}

// Extract a tempered pseudorandom number based on the mt.index-th value,
// calling generateNumbers() every 624 numbers
func (mt *MersenneTwister) ExtractNumber() uint32 {
	if mt.index == 0 {
		mt.generateNumbers()
	}

	y := mt.state[mt.index]
	y ^= (y >> 11)
	y ^= (y << 7) & 0x9d2c5680
	y ^= (y << 15) & 0xefc60000
	y ^= (y >> 18)

	mt.index = (mt.index + 1) % 624
	return y
}

// Generate an array of 624 untempered numbers
func (mt *MersenneTwister) generateNumbers() {
	for i := 0; i < 624; i++ {
		y := mt.state[i]&0x80000000 + mt.state[(i+1)%624]&0x7FFFFFFF
		mt.state[i] = mt.state[(i+397)%624] ^ (y >> 1)
		if (y % 2) == 1 { // y is odd
			mt.state[i] ^= 2567483615
		}
	}
}
