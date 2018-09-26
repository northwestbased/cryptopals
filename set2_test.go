package cryptopals

import (
	"testing"
	"encoding/base64"
	"log"
)

func Test_9(t *testing.T) {
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	actual := Pad([]byte("YELLOW SUBMARINE"), 20)
	if string(actual) != string(expected) {
		t.Errorf("Pad function error\nExpected: %v\nActual: %v", expected, actual)
	}
}

func Test_10(t *testing.T) {
	lines, _ := ReadFileByLine("input/10.txt")
	var ct []byte
	for _, l := range lines {
		dl, _ := base64.StdEncoding.DecodeString(l)
		ct = append(ct, dl...)
	}
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16,16)
	pt := AESInCBCModeDecrypt(ct, key, iv)

	log.Printf("Problem 10 plaintext:\n%v\n", string(pt))
}

func Test_10_Encrypt_Decrypt(t *testing.T) {
	pt := []byte("random plaintext string")
	pt = Pad(pt, 16)
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16,16)
	ct := AESInCBCModeEncrypt(pt, key, iv)
	newPt := AESInCBCModeDecrypt(ct, key, iv)
	if string(pt) != string(newPt[:len(pt)]) {
		t.Errorf("Decrypted plaintext doesn't match original:\nOriginal: %v\nDecrypted: %v", pt, newPt)
	}
}

func Test_11(t *testing.T) {
	log.Println("Problem 11 Testing:")
	for i:=0; i<10; i++ {
		DetectAESOrECB()
	}
}

func Test_12(t *testing.T) {
	log.Println("Problem 12 Output:")
	out := AttackECBSuffix()
	log.Println(string(out))
}

func Test_13(t *testing.T) {
	encrypt, decrypt := initProfileFunctions()
	p := profileFor("aaaaaaaaaaaaa")
	a := encrypt([]byte(p))
	firstTwoBlocks  := a[:32]
	adminBlock := encrypt([]byte(profileFor("aaaaaaaaaaadmin")))[16:32]
	decrypt(append(firstTwoBlocks, adminBlock...))
}
