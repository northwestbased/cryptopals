// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptopals

/*
Break an MD4 keyed MAC using length extension

Second verse, same as the first, but use MD4 instead of SHA-1. Having done this attack once against SHA-1, the MD4 variant should take much less time; mostly just the time you'll spend Googling for an implementation of MD4.
*/

import (
	"bytes"
	"encoding/binary"
	"log"
	"strings"
)

var (
	shift1  = []uint{3, 7, 11, 19}
	shift2  = []uint{3, 5, 9, 13}
	shift3  = []uint{3, 9, 11, 15}
	xIndex2 = []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
	xIndex3 = []uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
)

func _Block(state []uint32, p []byte) int {
	a := state[0]
	b := state[1]
	c := state[2]
	d := state[3]
	n := 0
	var X [16]uint32
	for len(p) >= _Chunk {
		aa, bb, cc, dd := a, b, c, d

		j := 0
		for i := 0; i < 16; i++ {
			X[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
			j += 4
		}

		// Round 1.
		for i := uint(0); i < 16; i++ {
			x := i
			s := shift1[i%4]
			f := ((c ^ d) & b) ^ d
			a += f + X[x]
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		// Round 2.
		for i := uint(0); i < 16; i++ {
			x := xIndex2[i]
			s := shift2[i%4]
			g := (b & c) | (b & d) | (c & d)
			a += g + X[x] + 0x5a827999
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		// Round 3.
		for i := uint(0); i < 16; i++ {
			x := xIndex3[i]
			s := shift3[i%4]
			h := b ^ c ^ d
			a += h + X[x] + 0x6ed9eba1
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		a += aa
		b += bb
		c += cc
		d += dd

		p = p[_Chunk:]
		n += _Chunk
	}

	state[0] = a
	state[1] = b
	state[2] = c
	state[3] = d
	return n
}

const (
	_Chunk = 64
	_Init0 = 0x67452301
	_Init1 = 0xEFCDAB89
	_Init2 = 0x98BADCFE
	_Init3 = 0x10325476
)

func MD4(in []byte) []byte {
	state := []uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476}

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	length := len(in)
	padding := MD4Padding(length)
	in = append(in, padding...)
	_Block(state, in)
	var out []byte
	for _, s := range state {
		out = append(out, byte(s>>0))
		out = append(out, byte(s>>8))
		out = append(out, byte(s>>16))
		out = append(out, byte(s>>24))
	}
	return out
}

func MD4Padding(length int) []byte {
	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	var padding []byte

	tmp[0] = 0x80
	if length%64 < 56 {
		padding = append(padding, tmp[0:56-length%64]...)
	} else {
		padding = append(padding, tmp[0:64+56-length%64]...)
	}

	// Length in bits.
	length <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(length >> (8 * i))
	}
	padding = append(padding, tmp[0:8]...)
	return padding
}

func MD4CustomInput(in []byte, state []uint32) []byte {

	_Block(state, in)
	var out []byte
	for _, s := range state {
		out = append(out, byte(s>>0))
		out = append(out, byte(s>>8))
		out = append(out, byte(s>>16))
		out = append(out, byte(s>>24))
	}
	return out
}

func CheckValidMD4MacUnderKeyFactory() (func([]byte) []byte, func([]byte, []byte) bool) {
	keyLen := GetRandomInt(30) + 5
	key := Key(keyLen)

	checkIfAdmin := func(str []byte, hash []byte) bool {
		if bytes.Equal(MD4(append(key, str...)), hash) && strings.Contains(string(str), ";admin=true") {
			return true
		} else {
			return false
		}
	}
	createHash := func(b []byte) []byte {
		if strings.Contains(string(b), ";admin=true") {
			panic("Someone is attacking!")
		}

		return MD4(append(key, b...))
	}
	return createHash, checkIfAdmin
}

func LengthExtendMD4() {
	val := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	postText := []byte(";admin=true")
	hash, checkHash := CheckValidMD4MacUnderKeyFactory()
	hashSum := hash(val)

	s0 := binary.LittleEndian.Uint32(hashSum[0:4])
	s1 := binary.LittleEndian.Uint32(hashSum[4:8])
	s2 := binary.LittleEndian.Uint32(hashSum[8:12])
	s3 := binary.LittleEndian.Uint32(hashSum[12:16])
	for i := 0; i < 100; i++ {
		keyLen := i
		initialPadding := MD4Padding(keyLen + len(val))

		newPadding := MD4Padding(keyLen + len(val) + len(postText) + len(initialPadding))
		sneakyHash := MD4CustomInput(append(postText, newPadding...), []uint32{s0, s1, s2, s3})

		fullText := append(val, initialPadding...)
		fullText = append(fullText, postText...)
		if checkHash(fullText, sneakyHash) {
			log.Println("found it")
			log.Println(sneakyHash)
		}
	}
}
