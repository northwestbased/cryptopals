package cryptopals

import (
	"encoding/base64"
	"log"
	"testing"
)

func Test_25(t *testing.T) {
	lines, err := ReadFileByLine("input/25.txt")
	if err != nil {
		t.Fatal(err)
	}

	var ct []byte
	for _, l := range lines {
		dl, _ := base64.StdEncoding.DecodeString(l)
		ct = append(ct, dl...)
	}

	pt := AESInECBModeDecrypt(ct, []byte("YELLOW SUBMARINE"))

	ct, updateFunc := CTRRandomAccessReadWrite(pt)
	pt = BreakCTRRandomAccess(ct, updateFunc)
	log.Println(string(pt))
}

func Test_26(t *testing.T) {
	log.Println(createBitflippedAdminCTR())
}

func Test_27(t *testing.T) {
	log.Println("out", findCBCKey())
}

func Test_28(t *testing.T) {
	log.Println(KeyedSHA1([]byte("key1"), []byte("val1")))
	log.Println(KeyedSHA1([]byte("key1"), []byte("val2")))
}
