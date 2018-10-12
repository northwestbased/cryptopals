package cryptopals

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

/*
Break HMAC-SHA1 with a slightly less artificial timing leak

Reduce the sleep in your "insecure_compare" until your previous solution breaks. (Try 5ms to start.)

Now break it again.
*/

func checkSignature2(w http.ResponseWriter, r *http.Request) {
	msDelay := 3
	//get arguments fromm request
	r.ParseForm()
	requiredArgs := []string{"file", "signature"}
	args := make(map[string]string)
	for k, v := range r.Form {
		args[k] = strings.Join(v, "")
	}
	if len(args) != len(requiredArgs) {
		returnError(w, http.StatusBadRequest, "400 Bad Request")
		return
	}
	for _, arg := range requiredArgs {
		if _, a := args[arg]; !a {
			returnError(w, http.StatusBadRequest, "400 Bad Request")
			return
		}
	}

	sig, err := hex.DecodeString(args["signature"])
	if err != nil {
		returnError(w, http.StatusBadRequest, "400 Bad Request")
		return
	}

	if insecureCompare([]byte(args["file"]), sig, key, msDelay) {
		fmt.Fprintf(w, "true")
		return
	}
	fmt.Fprintf(w, "false")
	return
}

func initIt2() {

	http.HandleFunc("/test", checkSignature2) // set router
	go http.ListenAndServe(":9090", nil)      // set listen port
	attackHMACServer2()
}

func attackHMACServer2() {
	msDelay := 3

	key := make([]byte, 20)

	msOffset := 0
	for i := 0; i < 20; i++ {
		var b int
		for b = 0; b < 256; b++ {
			key[i] = byte(b)
			t0 := time.Now().UnixNano() / int64(time.Millisecond)
			request(hex.EncodeToString(key))
			t1 := time.Now().UnixNano() / int64(time.Millisecond)
			if t1-t0 >= int64(msDelay*(i+1)+msOffset) {
				log.Println("val found", i, b)
				break
			}
		}
		if b == 256 {
			if i == 0 {
				panic("too smalll of delay")
			} else {
				log.Println("going back...")
				i -= 2
				msOffset += 1
			}
		}
	}
	v, _ := request(hex.EncodeToString(key))
	log.Println(v)
}
