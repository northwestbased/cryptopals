package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"log"
	"testing"
)

func Test_1(t *testing.T) {
	hex := "49276d206b696c6c696e6720796f757220627261696" +
	"e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaW" +
	"tlIGEgcG9pc29ub3VzIG11c2hyb29t"

	actual, err := HexToBase64(hex)

	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("Expected output: %s\nActual output: %s", expected, actual)
	}

}

func Test_2(t *testing.T) {
	buffer1 := "1c0111001f010100061a024b53535009181c"
	buffer2 := "686974207468652062756c6c277320657965"
	expected, _ := hex.DecodeString("746865206b696420646f6e277420706c6179")

	b1, e1 := hex.DecodeString(buffer1)
	b2, e2 := hex.DecodeString(buffer2)
	if e1 != nil {
		t.Fatal(e1)
	} else if e2 != nil {
		t.Fatal(e2)
	}
	actual := XOr(b1, b2)

	if string(actual) != string(expected) {
		t.Fatalf("Expected output: %v\nActual output: %v", []byte(expected), []byte(actual))
	}
}

func Test_3(t *testing.T) {
	ctHex := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	ct, _ := hex.DecodeString(ctHex)
	key, pt, freqDif := BreakSingleByteXOrCipher([]byte(ct))
	log.Printf("Challenge 3 Output:\nkey:%v frequency:%v\nPlaintext:\n%v", key, freqDif, string(pt))

}

func Test_4(t *testing.T) {
	lines, _ := ReadFileByLine("input/4.txt")
	foundCiphertext := false
	for _, line := range lines {
		bytes, _ := hex.DecodeString(line)
		if SingleByteXOrOracle(bytes) {
			if foundCiphertext {
				t.Fatal("Found more than one ciphertext")
			}
			foundCiphertext = true
			_, pt, _ := BreakSingleByteXOrCipher(bytes)
			log.Printf("Challenge 4 Plaintext: %s", string(pt))
		}
	}
	if !foundCiphertext {
		t.Fatal("Didn't detect a single byte xor ciphertext")
	}
}

func Test_5(t *testing.T) {
	pt := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	ct := RepeatingKeyXOrCipher(pt, []byte("ICE"))
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	if hex.EncodeToString(ct) != expected {
		t.Fatalf("Generated ciphertext doesn't match expected ciphertext.\nexpected: %v\nactual:   %v", expected, hex.EncodeToString(ct))
	}

	//test decryption
	ptOut := RepeatingKeyXOrCipher(ct, []byte("ICE"))
	if string(ptOut) != string(pt) {
		t.Fatalf("Decrypted plaintext doesn't match original plaintext.\nexpected: %v\nactual:   %v", string(ptOut), string(pt))
	}

}

func Test_HammingDistance(t *testing.T) {
	b1 := []byte("this is a test")
	b2 := []byte("wokka wokka!!!")
	hd := HammingDistance(b1, b2)
	if hd != 37 {
		t.Fatalf("Hamming Distance calculated as %v instead of 37", hd)
	}

}

func Test_6(t *testing.T) {
	lines, err := ReadFileByLine("input/6.txt")
	if err != nil {
		t.Error(err)
	}
	var ct []byte
	for _, l := range lines {
		dl, _ := base64.StdEncoding.DecodeString(l)
		ct = append(ct, dl...)
	}
	key := BreakRepeatingKeyXOrCipher(ct)
	plaintext := RepeatingKeyXOrCipher(ct, key)
	log.Printf("Challenge 6 Key: %v", string(key))
	log.Printf("Challenge 6 Plaintext:\n%v", string(plaintext))
}

func Test_7(t *testing.T) {
	lines, err := ReadFileByLine("input/7.txt")
	if err != nil {
		t.Fatal(err)
	}

	var ct []byte
	for _, l := range lines {
		dl, _ := base64.StdEncoding.DecodeString(l)
		ct = append(ct, dl...)
	}

	pt := AESInECBModeDecrypt(ct, []byte("YELLOW SUBMARINE"))

	log.Printf("Challenge 7 Plaintext:\n%v", string(pt))
}

func Test_8(t *testing.T) {
	lines, err := ReadFileByLine("input/8.txt")
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, l := range lines {
		dl, _ := hex.DecodeString(l)
		if AESInECBModeOracle(dl) {
			count += 1
			log.Printf("Challenge 8: found ECB-encrypted ciphertext:\n%v", dl)
		}
	}
	if count != 1 {
		t.Fatal("Wrong number of ECB-encrypted ciphertexts found.")
	}

}
