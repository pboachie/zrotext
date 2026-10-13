package main

import (
	"bufio"
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	hpke "github.com/pboachie/zrotext/sdk/native/hpke-candidate/go"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
)

func unhex(s string) []byte {
	v, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return v
}
func main() {
	scanner := bufio.NewScanner(io.LimitReader(os.Stdin, 1000001))
	scanner.Buffer(make([]byte, 4096), 1000000)
	rows, index := 0, 0
	previous := ""
	for scanner.Scan() {
		f := strings.Split(scanner.Text(), "\t")
		if len(f) != 9 {
			panic("columns")
		}
		if f[0] != previous {
			index = 0
			previous = f[0]
		}
		b, signer := unhex(f[2]), unhex(f[3])
		value, _ := strconv.Atoi(f[1])
		profile := byte(value)
		if _, err := hpke.VerifyEnvelope(b, signer, 5-profile); err == nil {
			panic("profile negotiation")
		}
		token, err := hpke.VerifyEnvelope(b, signer, profile)
		if err != nil {
			panic(err)
		}
		info, aad, err := token.WrapTranscript(index)
		if err != nil || !bytes.Equal(info, unhex(f[7])) || !bytes.Equal(aad, unhex(f[8])) || !bytes.Equal(token.BodyAAD(), unhex(f[4])) {
			panic("transcript")
		}
		if _, _, err = token.WrapTranscript(-1); err == nil {
			panic("index")
		}
		original := append([]byte(nil), b...)
		if profile == 3 {
			zero := append([]byte(nil), b...)
			clear(zero[26:42])
			if _, err := hpke.VerifyEnvelope(zero, signer, profile); err != hpke.ErrShape {
				panic("zero message shape")
			}
		}
		digest := token.UnsignedDigest()
		clear(b)
		if token.UnsignedDigest() != digest {
			panic("alias")
		}
		high := append([]byte(nil), original...)
		scalar := new(big.Int).SetBytes(high[len(high)-32:])
		scalar.Sub(elliptic.P256().Params().N, scalar).FillBytes(high[len(high)-32:])
		if _, err := hpke.VerifyEnvelope(high, signer, profile); err == nil {
			panic("high S")
		}
		for at := range original {
			bad := append([]byte(nil), original...)
			bad[at] ^= 128
			if _, err := hpke.VerifyEnvelope(bad, signer, profile); err == nil {
				panic("mutation")
			}
		}
		for _, size := range []int{0, 10, 425, len(original) - 1} {
			if _, err := hpke.VerifyEnvelope(original[:size], signer, profile); err == nil {
				panic("truncation")
			}
		}
		if _, err := hpke.VerifyEnvelope(append(original, 0), signer, profile); err == nil {
			panic("trailing")
		}
		rows++
		index++
	}
	if scanner.Err() != nil {
		panic(scanner.Err())
	}
	if rows != 6 {
		panic(fmt.Sprint("rows ", rows))
	}
	fmt.Println("6 envelope rows plus syntax/signature/alias negatives passed")
}
