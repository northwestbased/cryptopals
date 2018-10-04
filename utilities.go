package cryptopals

import (
	"bufio"
	"crypto/rand"
	"math/big"
	"os"
)

func ReadFileByLine(filename string) ([]string, error) {
	var lines []string

	file, err := os.Open(filename)
	if err != nil {
		return []string{}, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return []string{}, err
	}
	return lines, nil
}

func BreakIntoBlocks(buffer []byte, size int) [][]byte {
	if len(buffer)%size != 0 {
		panic("Buffer isn't a multiple of size")
	}
	var out [][]byte
	for i := 0; i < len(buffer); i += size {
		out = append(out, buffer[i:i+size])
	}
	return out
}

func Flatten(blocks [][]byte) []byte {
	var out []byte
	for _, block := range blocks {
		out = append(out, block...)
	}
	return out
}

func GetRandomInt(max int) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return int(nBig.Int64())
}

func Key(length int) []byte {
	if length < 1 {
		panic("Length needs to be a positive number")
	}
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return buf
}
