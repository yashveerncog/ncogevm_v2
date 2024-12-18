package cryptod

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// SignatureLength indicates the byte length required to carry a signature with recovery id.
const SignatureLength = 64 + 1 // 64 bytes MLDsa87 signature + 1 byte recovery id

// DigestLength sets the signature digest exact length
const DigestLength = 32

var errInvalidPubkey = errors.New("invalid MLDsa87 public key")

// KeccakState wraps sha3.state
type KeccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

func NewKeccakState() KeccakState {
	return sha3.NewLegacyKeccak512().(KeccakState)
}

func HashData(kh KeccakState, data []byte) (h common.Hash) {
	kh.Reset()
	kh.Write(data)
	kh.Read(h[:])
	return h
}

func Keccak512(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

/* func Keccak512Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	d.Read(h[:])
	return h
} */

func Keccak512Hash(data ...[]byte) (h common.Hash) {
	d := sha3.NewLegacyKeccak512()
	for _, b := range data {
		d.Write(b)
	}
	sum := d.Sum(nil) // Get the resulting hash
	copy(h[:], sum)   // Copy the first 32 bytes into h
	return h
}

func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(Keccak512(data)[12:])
}

func CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	return common.BytesToAddress(Keccak512([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:])
}

// ToMLDsa87 creates a private key with the given bytes.
func ToMLDsa87(d []byte) (*mldsa87.PrivateKey, error) {
	priv := new(mldsa87.PrivateKey)
	err := priv.UnmarshalBinary(d)
	if err != nil {
		return nil, errors.New("invalid MLDsa87 private key")
	}
	return priv, nil
}

func FromMLDsa87(priv *mldsa87.PrivateKey) []byte {
	b, _ := priv.MarshalBinary()
	return b
}

func UnmarshalPubkey(pub []byte) (*mldsa87.PublicKey, error) {
	var publicKey mldsa87.PublicKey
	err := publicKey.UnmarshalBinary(pub)
	if err != nil {
		return nil, errInvalidPubkey
	}
	return &publicKey, nil
}

func FromMLDsa87Pub(pub *mldsa87.PublicKey) []byte {
	b, _ := pub.MarshalBinary()
	return b
}

func HexToMLDsa87(hexkey string) (*mldsa87.PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if err != nil {
		return nil, err
	}
	return ToMLDsa87(b)
}

func LoadMLDsa87(file string) (*mldsa87.PrivateKey, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	r := bufio.NewReader(fd)
	buf := make([]byte, 64)
	n, err := readASCII(buf, r)
	if err != nil {
		return nil, err
	} else if n != len(buf) {
		return nil, fmt.Errorf("key file too short, want 64 hex characters")
	}
	if err := checkKeyFileEnd(r); err != nil {
		return nil, err
	}

	return HexToMLDsa87(string(buf))
}

func SaveMLDsa87(file string, key *mldsa87.PrivateKey) error {
	k := hex.EncodeToString(FromMLDsa87(key))
	return os.WriteFile(file, []byte(k), 0600)
}

/* func GenerateMLDsa87Key() (*mldsa87.PrivateKey, error) {
	_, sk, err := mldsa87.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return sk, nil // Return sk directly
} */

func GenerateMLDsa87Key() (*mldsa87.PrivateKey, error) {
	_, sk, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return sk, nil // sk is already a pointer to PrivateKey
}

/* func SignMLDsa87(priv *mldsa87.PrivateKey, hash []byte) ([]byte, error) {
	return mldsa87.Sign(priv, hash)
} */

// SignMLDsa87 signs the given message hash using the MLDsa87 private key.
func SignMLDsa87(priv *mldsa87.PrivateKey, msg []byte) ([]byte, error) {
	// Sign with nil SignerOpts since MLDsa87 does not support pre-hashed messages.
	return priv.Sign(rand.Reader, msg, crypto.Hash(0))
}

/* func ValidateMLDsa87Signature(pub *mldsa87.PublicKey, hash []byte, sig []byte) bool {
	return mldsa87.Verify(pub, hash, sig)
} */

// ValidateMLDsa87Signature verifies the signature using the public key, hash, and signature.
func ValidateMLDsa87Signature(pub *mldsa87.PublicKey, msg []byte, sig []byte) bool {
	// Pass `nil` as the context string since we are not using any.
	return mldsa87.Verify(pub, msg, nil, sig)
}

func PubkeyToAddress(pub mldsa87.PublicKey) common.Address {
	pubBytes, _ := pub.MarshalBinary()
	return common.BytesToAddress(Keccak512(pubBytes)[12:])
}

/* func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
} */

func readASCII(buf []byte, r *bufio.Reader) (n int, err error) {
	for ; n < len(buf); n++ {
		buf[n], err = r.ReadByte()
		switch {
		case err == io.EOF || buf[n] < '!':
			return n, nil
		case err != nil:
			return n, err
		}
	}
	return n, nil
}

func checkKeyFileEnd(r *bufio.Reader) error {
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case b != '\n' && b != '\r':
			return fmt.Errorf("invalid character %q at end of key file", b)
		case i >= 2:
			return errors.New("key file too long, want 64 hex characters")
		}
	}
}

/*
ToECDSA -->> ToMLDsa87
FromECDSA -->> FromMLDsa87
HexToECDSA -->> HexToMLDsa87
LoadECDSA -->> LoadMLDsa87
SaveECDSA -->> SaveMLDsa87
GenerateKey -->> GenerateMLDsa87Key
Sign -->> SignMLDsa87
*/
