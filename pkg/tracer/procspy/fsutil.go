package procspy

import (
	"bytes"
	"os"
)

// readFile reads an arbitrary file into a buffer.
func readFile(filename string, buf *bytes.Buffer) (int64, error) {
	f, err := os.Open(filename)
	if err != nil {
		return -1, err
	}
	defer f.Close()
	return buf.ReadFrom(f)
}

func ReadDirNames(path string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return fh.Readdirnames(-1)
}
