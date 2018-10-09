package cryptopals

import (
	"encoding/base64"
	"encoding/binary"
	"log"
	"strconv"
	"strings"
	"time"
)

func GetRandomString() []byte {
	plaintexts := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	index := GetRandomInt(len(plaintexts))
	decoded, err := base64.StdEncoding.DecodeString(plaintexts[index])
	if err != nil {
		panic(err)
	}
	return decoded
}

func CBCServerMockup() (ct, iv []byte, checkPadding func([]byte) bool) {
	pt := []byte(GetRandomString())
	pt = Pad(pt, 16)

	key := Key(16)

	//values we are returning:
	iv = Key(16)
	ct = AESInCBCModeEncrypt(pt, key, iv)
	checkPadding = func(ct []byte) bool {
		pt := AESInCBCModeDecrypt(ct, key, iv)
		_, err := StripPadding(pt)
		if err != nil {
			return false
		}
		return true
	}

	return
}

func CBCPaddingOracle() []byte {
	var out []byte
	ct, iv, decrypt := CBCServerMockup()
	blocks := BreakIntoBlocks(ct, 16)
	iv2 := [][]byte{iv}
	blocks = append(iv2, blocks...)
	for b := 1; b < len(blocks); b++ {
		target := blocks[b]
		prev := make([]byte, 16)
		copy(prev, blocks[b-1])

		//find initial padding for block
		initialPadding := 0

		if decrypt(append(prev, target...)) {
			prevCopy := make([]byte, 16)
			copy(prevCopy, prev)
			i := -1
			for decrypt(append(prevCopy, target...)) {
				i++
				prevCopy[i] ^= 0xFF
			}
			initialPadding = 16 - i
		}

		for padding := initialPadding; padding <= 15; padding++ {
			targetChar := 16 - padding - 1
			newPaddingVal := padding + 1
			for i := targetChar + 1; i < 16; i++ {
				prev[i] ^= byte(padding) ^ byte(newPaddingVal)
			}

			i := 0
			for i = 0; i < 256; i++ {
				prev[targetChar] = byte(i)
				if decrypt(append(prev, target...)) {
					break
				}

			}
		}
		v := XOr(prev, blocks[b-1])
		out = append(out, SingleByteXOrCipher(v, 16)...)
	}
	return out
}

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

func BreakCTRManually() {
	nonce := Key(8)
	key := Key(16)

	lines, err := ReadFileByLine("input/19.txt")
	if err != nil {
		panic(err)
	}
	var ciphertexts [][]byte
	for _, line := range lines {
		plaintext, _ := base64.StdEncoding.DecodeString(line)
		ciphertext := CTR_Cipher(plaintext, key, nonce)
		ciphertexts = append(ciphertexts, ciphertext)
	}

	input, err := ReadFileByLine("input/19_guesses.txt")
	if err != nil {
		return
	}
	first := []byte(input[0])

	var ciphertext []byte
	for _, ct := range ciphertexts {
		if len(ct) > len(ciphertext) {
			ciphertext = ct
		}
	}

	var guessedKey []byte

	for index, letter := range first {
		ciphertextByte := ciphertext[index]
		keyByte := ciphertextByte ^ byte(letter)
		guessedKey = append(guessedKey, keyByte)
	}
	for _, ct := range ciphertexts {
		longest := len(ct)
		if len(guessedKey) < longest {
			longest = len(guessedKey)
		}
		log.Println(string(XOr(guessedKey[:longest], ct[:longest])))
	}
}

func BreakCTRStatistically() {
	nonce := Key(8)
	key := Key(16)

	lines, _ := ReadFileByLine("input/19.txt")
	minLength := -1
	for _, line := range lines {
		l, _ := base64.StdEncoding.DecodeString(line)

		if len(l) < minLength || minLength == -1 {
			minLength = len(l)
		}
	}

	var ciphertext []byte
	for _, line := range lines {
		l, _ := base64.StdEncoding.DecodeString(line)

		l = CTR_Cipher(l, key, nonce)
		ciphertext = append(ciphertext, l[:minLength]...)
	}
	key = BreakRepeatingKeyXOrCipher(ciphertext)
	blocks := BreakIntoBlocks(RepeatingKeyXOrCipher(ciphertext, key), minLength)
	for _, b := range blocks {
		log.Println(string(b))
	}
}

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

func WaitThenGenerateNum() uint32 {
	mt := MersenneTwister{}
	wait1 := GetRandomInt(960) + 40
	wait2 := GetRandomInt(960) + 40
	time.Sleep(time.Duration(wait1) * time.Second)
	mt.init(uint32(time.Now().Unix()))
	log.Println("seed done")
	time.Sleep(time.Duration(wait2) * time.Second)
	return mt.ExtractNumber()
}

func CrackSeed(firstNum uint32) {
	t := time.Now().Unix()
	for i := 0; i < 3000; i++ {
		mt := MersenneTwister{}
		seed := uint32(t - int64(i))
		log.Println(seed)

		mt.init(seed)
		if mt.ExtractNumber() == firstNum {
			log.Printf("found that seed!!!!! seed %v %v", seed, i)
			return
		}
	}
	log.Println("did not find seed")
}

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

func MT19937StreamCipher(text []byte, key uint16) []byte {
	var output []byte

	mt := MersenneTwister{}
	mt.init(uint32(key))
	var keyStreamBuffer []byte
	for _, t := range text {
		if len(keyStreamBuffer) == 0 {
			num := mt.ExtractNumber()
			str := strconv.Itoa(int(num))
			keyStreamBuffer = append(keyStreamBuffer, []byte(str)...)
		}
		output = append(output, t^keyStreamBuffer[0])
		keyStreamBuffer = keyStreamBuffer[1:]
	}
	return output
}

func MT19937StreamCipherEncryptWithPrefix(text []byte) []byte {
	key := uint16(GetRandomInt(0x10000))
	prefixLength := GetRandomInt(1000)
	prefix := Key(prefixLength)
	text = append(prefix, text...)
	return MT19937StreamCipher(text, key)
}

func BreakMTStreamCipherWithPrefix() {
	ct := MT19937StreamCipherEncryptWithPrefix([]byte("AAAAAAAAAAAAAAAAAAA"))
	for i := 0; i < 0x10000; i++ {
		key := uint16(i)
		out := MT19937StreamCipher(ct, key)
		if strings.Contains(string(out), "AAAAAAAAAAAAAAAAAAA") {
			log.Println("found it!", key, out)
		}
	}

}

func CreatePasswordResetToken() []byte {
	seed := uint32(time.Now().Unix())
	prefixLength := GetRandomInt(1000)
	prefix := Key(prefixLength)
	text := append(prefix, []byte("password reset")...)
	return MT19937StreamCipher(text, uint16(seed))
}

func CheckPasswordResetToken(ct []byte) bool {
	time := uint16(time.Now().Unix())
	for i := 0; i < 10; i++ {
		pt := MT19937StreamCipher(ct, uint16(time-uint16(i)))
		if strings.Contains(string(pt), "password reset") {
			return true
		}
	}
	return false
}
