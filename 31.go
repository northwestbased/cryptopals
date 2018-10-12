package cryptopals

/*
Implement and break HMAC-SHA1 with an artificial timing leak

The psuedocode on Wikipedia should be enough. HMAC is very easy.

Using the web framework of your choosing (Sinatra, web.py, whatever), write a tiny application that has a URL that takes a "file" argument and a "signature" argument, like so:

http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51

Have the server generate an HMAC key, and then verify that the "signature" on incoming requests is valid for "file", using the "==" operator to compare the valid MAC for a file with the "signature" parameter (in other words, verify the HMAC the way any normal programmer would verify it).

Write a function, call it "insecure_compare", that implements the == operation by doing byte-at-a-time comparisons with early exit (ie, return false at the first non-matching byte).

In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms after each byte).

Use your "insecure_compare" function to verify the HMACs on incoming requests, and test that the whole contraption works. Return a 500 if the MAC is invalid, and a 200 if it's OK.

Using the timing leak in this application, write a program that discovers the valid MAC for any file.
*/

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

var key = Key(16)

func SHA1Hmac(key, message []byte) []byte {
	blockSize := 64
	//Keys longer than blockSize are shortened by hashing them
	if len(key) > blockSize {
		key = SHA1(key)
	}

	//Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
	if len(key) < blockSize {
		key = append(key, make([]byte, blockSize-len(key))...)
	}

	//0x730
	//0x438

	var iKeyPad, oKeyPad []byte
	for i := 0; i < len(key); i++ {
		oKeyPad = append(oKeyPad, key[i]^0x5C)
		iKeyPad = append(iKeyPad, key[i]^0x36)
	}

	h1 := SHA1(append(iKeyPad, message...))
	return SHA1(append(oKeyPad, h1...))
}

func insecureCompare(fileName, actualHmac, key []byte, msDelay int) bool {
	expectedHmac := SHA1Hmac(key, fileName)
	if len(actualHmac) != len(expectedHmac) {
		return false
	}
	for i, c := range expectedHmac {
		if c != actualHmac[i] {
			return false
		}

		time.Sleep(time.Duration(msDelay * 1000000))
	}
	return true
}

func checkSignature(w http.ResponseWriter, r *http.Request) {
	msDelay := 10
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

func returnError(w http.ResponseWriter, code int, s string) {
	w.WriteHeader(code)
	fmt.Fprint(w, s)
	return
}

func initIt() {

	http.HandleFunc("/test", checkSignature) // set router
	go http.ListenAndServe(":9090", nil)     // set listen port
	attackHMACServer()
}

func attackHMACServer() {
	hash := make([]byte, 20)
	msDelay := 10

	for i := 0; i < 20; i++ {
		var b int
		for b = 0; b < 256; b++ {
			hash[i] = byte(b)
			t0 := time.Now().UnixNano() / int64(time.Millisecond)
			request(hex.EncodeToString(hash))
			t1 := time.Now().UnixNano() / int64(time.Millisecond)
			if t1-t0 >= int64(msDelay*(i+1)) {
				break
			}
		}
		log.Println(i, b)
	}
	v, _ := request(hex.EncodeToString(hash))
	log.Println(v)
}

func request(hexSig string) (string, error) {
	payload := "?file=file&signature=" + hexSig
	rs, err := http.Get("http://localhost:9090/test" + payload)
	// Process response
	if err != nil {
		return "", err
	}
	defer rs.Body.Close()

	bodyBytes, err := ioutil.ReadAll(rs.Body)
	if err != nil {
		panic(err)
	}

	bodyString := string(bodyBytes)
	return bodyString, nil
}
