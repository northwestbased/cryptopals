package cryptopals

import (
	"encoding/hex"
	"log"
	"testing"
)

func Test_1(t *testing.T) {
	hex := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expectedOut := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	actualOut, err := HexToBase64(hex)

	if err != nil {
		t.Error(err)
	}
	if actualOut != expectedOut {
		t.Errorf("Expected output: %s\nActual output: %s", expectedOut, actualOut)
	}

}

func Test_2(t *testing.T) {
	buffer1 := "1c0111001f010100061a024b53535009181c"
	buffer2 := "686974207468652062756c6c277320657965"
	expectedResult := "746865206b696420646f6e277420706c6179"

	b1, e1 := hex.DecodeString(buffer1)
	b2, e2 := hex.DecodeString(buffer2)
	if e1 != nil {
		t.Error(e1)
	} else if e2 != nil {
		t.Error(e2)
	}
	result, err := XOrBuffers(b1, b2)
	if err != nil {
		t.Error(err)
	}
	if hex.EncodeToString(result) != expectedResult {
		t.Errorf("Expected output: %s\nActual output: %s", expectedResult, result)
	}
}

func Test_3(t *testing.T) {
	ctHex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	ct, _ := hex.DecodeString(ctHex)
	_, pt, _ := BreakSingleByteXOr([]byte(ct))
	log.Printf("Challenge 3 Plaintext: %s\n", string(pt))

}

func Test_4(t *testing.T) {
	lines, _ := ReadFileByLine("input/4.txt")
	foundCiphertext := false
	for _, line := range lines {
		bytes, _ := hex.DecodeString(line)
		if SingleByteXOrOracle(bytes) {
			if foundCiphertext {
				t.Error("Found more than one ciphertext")
			}
			foundCiphertext = true
			_, pt, _ := BreakSingleByteXOr(bytes)
			log.Printf("Challenge 4 Plaintext: %s\n", string(pt))
		}
	}
}

func Test_5(t *testing.T) {
	pt := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	ct := RepeatingKeyXOrCipher(pt, []byte("ICE"))
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if hex.EncodeToString(ct) != expected {
		log.Printf("it's all wrong")
		log.Printf(hex.EncodeToString(ct))
		log.Printf(expected)
	}

}
