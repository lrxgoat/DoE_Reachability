package metrics

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"golang.org/x/crypto/hkdf"
)

// https://github.com/marten-seemann/qtls-go1-15/blob/0d137e9e3594d8e9c864519eff97b323321e5e74/cipher_suites.go#L281
type aead interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	explicitNonceLen() int
}

const (
	aeadNonceLength   = 12
	noncePrefixLength = 4
)

// https://github.com/marten-seemann/qtls-go1-15/blob/0d137e9e3594d8e9c864519eff97b323321e5e74/cipher_suites.go#L375
func aeadAESGCMTLS13(key, nonceMask []byte) aead {
	//if len(nonceMask) != aeadNonceLength {
	//	//return aead(s), "wrong nonce length"
	//	panic("tls: internal error: wrong nonce length")
	//}
	aesout, _ := aes.NewCipher(key)
	//if err != nil {
	//	panic(err)
	//}
	aeadout, _ := cipher.NewGCM(aesout)
	//if err != nil {
	//	panic(err)
	//}
	ret := &xorNonceAEAD{aead: aeadout}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// xoredNonceAEAD wraps an AEAD by XORing in a fixed pattern to the nonce before each call.
// https://github.com/marten-seemann/qtls-go1-15/blob/0d137e9e3594d8e9c864519eff97b323321e5e74/cipher_suites.go#L319
type xorNonceAEAD struct {
	nonceMask [aeadNonceLength]byte
	aead      cipher.AEAD
}

func (f *xorNonceAEAD) NonceSize() int        { return 8 } // 64-bit sequence number
func (f *xorNonceAEAD) Overhead() int         { return f.aead.Overhead() }
func (f *xorNonceAEAD) explicitNonceLen() int { return 0 }

func (f *xorNonceAEAD) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result := f.aead.Seal(out, f.nonceMask[:], plaintext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	return result
}

func (f *xorNonceAEAD) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	result, err := f.aead.Open(out, f.nonceMask[:], ciphertext, additionalData)
	for i, b := range nonce {
		f.nonceMask[4+i] ^= b
	}
	return result, err
}

// hkdfExpandLabel HKDF expands a label.
// https://github.com/lucas-clemente/quic-go/blob/master/internal/handshake/hkdf.go
func hkdfExpandLabel(hash crypto.Hash, secret, context []byte, label string, length int) ([]byte, string) {
	b := make([]byte, 3, 3+6+len(label)+1+len(context))
	binary.BigEndian.PutUint16(b, uint16(length))
	b[2] = uint8(6 + len(label))
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = b[:3+6+len(label)+1]
	b[3+6+len(label)] = uint8(len(context))
	b = append(b, context...)

	out := make([]byte, length)
	n, err := hkdf.Expand(hash.New, secret, b).Read(out)
	if err != nil || n != length {
		return out, "HKDF err"
		//panic("quic: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out, ""
}

// computeSecrets computes the initial secrets based on the destination connection ID.
// https://www.rfc-editor.org/rfc/rfc9001.html#name-initial-secrets
func computeSecrets(destConnID []byte) ([]byte, []byte, string) {
	initialSalt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	// initial_secret = HKDF-Extract(initial_salt,client_dst_connection_id)
	initialSecret := hkdf.Extract(crypto.SHA256.New, destConnID, initialSalt)
	// client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32) = c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea
	clientSecret, err1 := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "client in", crypto.SHA256.Size())
	if err1 != "" {
		return clientSecret, clientSecret, err1
	}
	serverSecret, err2 := hkdfExpandLabel(crypto.SHA256, initialSecret, []byte{}, "server in", crypto.SHA256.Size())
	if err2 != "" {
		return clientSecret, serverSecret, err2
	}
	return clientSecret, serverSecret, ""
}

// computeInitialKeyAndIV derives the packet protection key and Initialization Vector (IV)
// from the initial secret.
// https://www.rfc-editor.org/rfc/rfc9001.html#protection-keys
func computeInitialKeyAndIV(secret []byte) ([]byte, []byte, string) {
	key, err1 := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic key", 16)
	if err1 != "" {
		return key, key, err1
	}
	iv, err2 := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic iv", 12)
	if err2 != "" {
		return key, iv, err2
	}
	return key, iv, ""
}

// computeHP derives the header protection key from the initial secret.
// https://www.rfc-editor.org/rfc/rfc9001.html#protection-keys
func computeHP(secret []byte) ([]byte, string) {
	hp, err := hkdfExpandLabel(crypto.SHA256, secret, []byte{}, "quic hp", 16)
	if err != "" {
		return hp, err
	}
	return hp, ""
}
