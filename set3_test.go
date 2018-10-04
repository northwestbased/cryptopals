package cryptopals

import (
	"encoding/base64"
	"log"
	"testing"
)

func Test_17(t *testing.T) {
	log.Printf("17 output:\n%v", string(CBCPaddingOracle()))
}

func Test_18(t *testing.T) {
	ciphertext, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("YELLOW SUBMARINE")
	nonce := make([]byte, 8)
	log.Printf("18 output:\n%v", string(CTR_Cipher(ciphertext, key, nonce)))
}

func Test_19(t *testing.T) {
	log.Printf("19")
	BreakCTRManually()
}

func Test_20(t *testing.T) {
	log.Printf("20")
	BreakCTRStatistically()
}
