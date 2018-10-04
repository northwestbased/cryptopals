package cryptopals

import (
	"encoding/base64"
	"log"
	"testing"
)

func Test_9(t *testing.T) {
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	actual := Pad([]byte("YELLOW SUBMARINE"), 20)
	if string(actual) != string(expected) {
		t.Fatalf("Pad function error\nExpected: %v\nActual: %v", expected, actual)
	}
}

func Test_10(t *testing.T) {
	lines, err := ReadFileByLine("input/10.txt")
	if err != nil {
		panic(err)
	}
	var ct []byte
	for _, l := range lines {
		dl, err := base64.StdEncoding.DecodeString(l)
		if err != nil {
			panic(err)
		}
		ct = append(ct, dl...)
	}
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16, 16)
	pt := AESInCBCModeDecrypt(ct, key, iv)

	log.Printf("Problem 10 plaintext:\n%v\n", string(pt))
}

func Test_10_Encrypt_Decrypt(t *testing.T) {
	pt := []byte("random plaintext string")
	pt = Pad(pt, 16)
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16, 16)
	ct := AESInCBCModeEncrypt(pt, key, iv)
	newPt := AESInCBCModeDecrypt(ct, key, iv)
	if string(pt) != string(newPt[:len(pt)]) {
		t.Fatalf("Decrypted plaintext doesn't match original:\nOriginal: %v\nDecrypted: %v", pt, newPt)
	}
}

func Test_11(t *testing.T) {
	log.Print("Problem 11 Testing:")
	for i := 0; i < 10; i++ {
		DetectAESOrECB()
	}
}

func Test_12(t *testing.T) {
	log.Print("Problem 12 Output:")
	out := AttackECBSuffix()
	log.Print(string(out))
}

func Test_13(t *testing.T) {
	if !createAdminProfile() {
		t.Fatal("Admin profile creation not succeesful")
	}
}

func Test_14(t *testing.T) {
	log.Print("\n\n\nProblem 14 Output:")
	out := AttackECBSuffixWithPrefix()
	log.Print(string(out))
}

func Test_15(t *testing.T) {
	out, err := StripPadding([]byte("ICE ICE BABY\x04\x04\x04\x04"))
	if err != nil {
		t.Fatal("Text stripping error")
	}
	if string(out) != "ICE ICE BABY" {
		t.Fatal("Text stripping error")
	}
	_, err = StripPadding([]byte("ICE ICE BABY\x05\x05\x05\x05"))
	if err == nil {
		t.Fatal("Text stripping error")
	}
}

func Test_16(t *testing.T) {
	isAdmin := createBitflippedAdmin()
	if !isAdmin {
		t.Fatal("Admin account creation not successful")
	}
}
