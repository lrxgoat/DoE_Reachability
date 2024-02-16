package metrics

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	random "math/rand"
	"strconv"
	"strings"
	"time"

	_ "crypto/sha256"
)

// A ConnectionID in QUIC
type ConnectionID []byte

const maxConnectionIDLen = 18
const MinConnectionIDLenInitial = 8
const DefaultConnectionIDLength = 16

// buildHeader creates the unprotected QUIC header.
// https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-packet
func buildHeader(destConnID, srcConnID ConnectionID, payloadLen int) []byte {
	hdr := []byte{0xc3} // long header type, fixed

	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, uint32(0xbabababa))
	hdr = append(hdr, version...) // version

	lendID := uint8(len(destConnID))
	hdr = append(hdr, lendID)        // destination connection ID length
	hdr = append(hdr, destConnID...) // destination connection ID

	lensID := uint8(len(srcConnID))
	hdr = append(hdr, lensID)       // source connection ID length
	hdr = append(hdr, srcConnID...) // source connection ID

	hdr = append(hdr, 0x0) // token length

	remainder := 4 + payloadLen
	remainder_mask := 0b100000000000000
	remainder_mask |= remainder
	remainder_b := make([]byte, 2)
	binary.BigEndian.PutUint16(remainder_b, uint16(remainder_mask))
	hdr = append(hdr, remainder_b...) // remainder length: packet number + encrypted payload

	pn := make([]byte, 4)
	binary.BigEndian.PutUint32(pn, uint32(2))
	hdr = append(hdr, pn...) // packet number

	return hdr
}

// buildPacket constructs an Initial QUIC packet
// and applies Initial protection.
// https://www.rfc-editor.org/rfc/rfc9001.html#name-client-initial
func buildPacket() ([]byte, ConnectionID, ConnectionID, string) {
	destConnID, srcConnID, genErr := generateConnectionIDs()
	if genErr != "" {
		return destConnID, destConnID, srcConnID, genErr
	}
	// generate random payload
	minPayloadSize := 1200 - 14 - (len(destConnID) + len(srcConnID))
	randomPayload := make([]byte, minPayloadSize)
	random.Seed(time.Now().UnixNano())
	random.Read(randomPayload)

	clientSecret, _, secErr := computeSecrets(destConnID)
	if secErr != "" {
		return clientSecret, destConnID, srcConnID, secErr
	}
	encrypted, encErr := encryptPayload(randomPayload, destConnID, clientSecret)
	if encErr != "" {
		return clientSecret, destConnID, srcConnID, encErr
	}
	hdr := buildHeader(destConnID, srcConnID, len(encrypted))
	raw := append(hdr, encrypted...)

	raw, encErr = encryptHeader(raw, hdr, clientSecret)
	if encErr != "" {
		return clientSecret, destConnID, srcConnID, encErr
	}
	return raw, destConnID, srcConnID, ""
}

// encryptHeader applies header protection to the packet bytes (raw).
// https://www.rfc-editor.org/rfc/rfc9001.html#name-client-initial
// https://www.rfc-editor.org/rfc/rfc9001.html#name-header-protection
func encryptHeader(raw, hdr, clientSecret []byte) ([]byte, string) {
	hp, comerr := computeHP(clientSecret)
	if comerr != "" {
		return hp, comerr
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return hp, "Aes NewCipher Err"
		//panic(fmt.Sprintf("error creating new AES cipher: %s", err))
	}
	hdroffset := 0
	payloadOffset := len(hdr)
	sample := raw[payloadOffset : payloadOffset+16]

	mask := make([]byte, block.BlockSize())
	if len(sample) != len(mask) {
		return hp, "invalid sample size"
		//panic("invalid sample size")
	}
	block.Encrypt(mask, sample)

	pnOffset := len(hdr) - 4
	pnBytes := raw[pnOffset:payloadOffset]
	raw[hdroffset] ^= mask[0] & 0xf
	for i := range pnBytes {
		pnBytes[i] ^= mask[i+1]
	}
	return raw, ""
}

// encryptPayload encrypts the payload of the packet.
// https://www.rfc-editor.org/rfc/rfc9001.html#name-packet-protection
func encryptPayload(payload, destConnID ConnectionID, clientSecret []byte) ([]byte, string) {
	myKey, myIV, err := computeInitialKeyAndIV(clientSecret)
	if err != "" {
		return myKey, err
	}
	encrypter := aeadAESGCMTLS13(myKey, myIV)

	nonceBuf := make([]byte, encrypter.NonceSize())
	var pn int64 = 2
	binary.BigEndian.PutUint64(nonceBuf[len(nonceBuf)-8:], uint64(pn))

	encrypted := encrypter.Seal(nil, nonceBuf, payload, nil)
	return encrypted, ""
}

// generateConnectionID generates a connection ID using cryptographic random
func generateConnectionID(len int) (ConnectionID, error) {
	b := make([]byte, len)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return ConnectionID(b), nil
}

// generateConnectionIDForInitial generates a connection ID for the Initial packet.
// It uses a length randomly chosen between 8 and 18 bytes.
func generateConnectionIDForInitial() (ConnectionID, error) {
	r := make([]byte, 1)
	if _, err := rand.Read(r); err != nil {
		return nil, err
	}
	len := MinConnectionIDLenInitial + int(r[0])%(maxConnectionIDLen-MinConnectionIDLenInitial+1)
	return generateConnectionID(len)
}

// generateConnectionIDs generates a destination and source connection ID.
func generateConnectionIDs() ([]byte, []byte, string) {
	destConnID, err := generateConnectionIDForInitial()
	if err != nil {
		return destConnID, destConnID, "generate destConnID err"
	}
	//checkError(err)
	srcConnID, err := generateConnectionID(DefaultConnectionIDLength)
	if err != nil {
		return destConnID, srcConnID, "generate srcConnID err"
	}
	//checkError(err)
	return destConnID, srcConnID, ""
}

// dissectVersionNegotiation dissects the Version Negotiation response
// and prints it to the command line.
// https://www.rfc-editor.org/rfc/rfc9000.html#name-version-negotiation-packet
func dissectVersionNegotiation(i []byte, dstID, srcID ConnectionID) (string, string) {
	firstByte := uint8(i[0])
	mask := 0b10000000
	mask &= int(firstByte)
	if mask == 0 {
		//fmt.Println("not a long header packet")
		return "", "not a long header packet"
	}

	versionBytes := i[1:5]
	v := binary.BigEndian.Uint32(versionBytes)
	if v != 0 {
		//fmt.Println("unexpected version in Version Negotiation packet")
		return "", "unexpected version"
	}

	dstLength := i[5]
	offset := 6 + uint8(dstLength)
	dst := i[6:offset]
	if hex.EncodeToString(dst) != hex.EncodeToString(srcID) {
		//fmt.Println("unexpected destination connection ID in response", dst, dstID)
		return "", "unexpected dst ID"
	}
	srcLength := i[offset]
	src := i[offset+1 : offset+1+srcLength]
	offset = offset + 1 + srcLength
	if hex.EncodeToString(src) != hex.EncodeToString(dstID) {
		//fmt.Println("unexpected source connection ID in response", dst, dstID)
		return "", "unexpected src ID"
	}

	n := uint8(len(i))
	//fmt.Println("Supported Versions:")
	serverQUICVer := ""
	for offset < n {
		supportedVersion := binary.BigEndian.Uint32(i[offset : offset+4])
		serverQUICVer += strconv.FormatUint(uint64(supportedVersion), 16) + ";"
		offset += 4
	}
	serverQUICVer = strings.TrimRight(serverQUICVer, ";")
	return serverQUICVer, ""
}

// checkError does error handling
//func checkError(err error) {
//	if err != nil {
//		fmt.Fprintf(os.Stderr, "Fatal error ", err.Error())
//		os.Exit(1)
//	}
//}
