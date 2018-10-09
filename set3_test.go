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

func Test_21(t *testing.T) {
	log.Printf("Mersenne Twister's first 3 outputs:")
	mt := MersenneTwister{}
	mt.init(100)
	log.Println(mt.ExtractNumber())
	log.Println(mt.ExtractNumber())
	log.Println(mt.ExtractNumber())
}

func Test_22(t *testing.T) {
	//num := WaitThenGenerateNum()
	//log.Println("num is", num)
	//CrackSeed(num)
	//commenting the above three lines out for now... they take too long!
}

func Test_23(t *testing.T) {
	mt := MersenneTwister{}
	mt.init(uint32(GetRandomInt(0x100000000)))
	var numbers []uint32
	for i := 0; i < 624; i++ {
		numbers = append(numbers, mt.ExtractNumber())
	}
	newState := CloneMTwisterState(numbers)
	mtCopy := MersenneTwister{}
	mtCopy.state = newState
	if mtCopy.ExtractNumber() != mt.ExtractNumber() {
		t.Fatal("didn't work")
	}
	log.Println(mtCopy.ExtractNumber(), mt.ExtractNumber())
	log.Println(mtCopy.ExtractNumber(), mt.ExtractNumber())
	log.Println(mtCopy.ExtractNumber(), mt.ExtractNumber())

}

func Test_24(t *testing.T) {
	BreakMTStreamCipherWithPrefix()

	ct := CreatePasswordResetToken()
	log.Println("valid token?", CheckPasswordResetToken(ct))
}
