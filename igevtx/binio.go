package igevtx
// (c) 2019, igosha (2igosha@gmail.com)

import (
	"io"
	"encoding/binary"
)

func readByte(rd io.Reader) (byte, error) {
	var buf [1]byte
	if _, err := io.ReadFull(rd, buf[:]); err != nil {
		return 0, err
	}
	return buf[0], nil
}

func readWord(rd io.Reader) (uint16, error) {
	var buf [2]byte
	if _, err := io.ReadFull(rd, buf[:]); err != nil {
		return 0, err
	}
	dw := binary.LittleEndian.Uint16(buf[:])
	return dw, nil
}

func readWordN(rd io.Reader, n []uint16) error {
	var buf [2]byte
	for i := 0; i < len(n); i++ {
		if _, err := io.ReadFull(rd, buf[:]); err != nil {
			return err
		}
		n[i] = binary.LittleEndian.Uint16(buf[:])
	}
	return nil
}

func readDword(rd io.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(rd, buf[:]); err != nil {
		return 0, err
	}
	dw := binary.LittleEndian.Uint32(buf[:])
	return dw, nil
}

func readInt32(rd io.Reader) (int32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(rd, buf[:]); err != nil {
		return 0, err
	}
	dw := int32(binary.LittleEndian.Uint32(buf[:]))
	return dw, nil
}

func readQword(rd io.Reader) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(rd, buf[:]); err != nil {
		return 0, err
	}
	dw := binary.LittleEndian.Uint64(buf[:])
	return dw, nil
}

func readInt64(rd io.Reader) (int64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(rd, buf[:]); err != nil {
		return 0, err
	}
	dw := int64(binary.LittleEndian.Uint64(buf[:]))
	return dw, nil
}

