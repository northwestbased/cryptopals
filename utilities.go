package cryptopals

import (
	"bufio"
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
