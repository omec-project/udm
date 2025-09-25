// SPDX-FileCopyrightText: 2025 Intel Corporation
// Copyright 2019 Communication Service/Software Laboratory, National Chiao Tung University (free5gc.org)
//
// SPDX-License-Identifier: Apache-2.0

package suci

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"strconv"
	"strings"

	"github.com/omec-project/util/logger"
	"golang.org/x/crypto/curve25519"
)

type SuciProfile struct {
	ProtectionScheme string `yaml:"ProtectionScheme,omitempty"`
	PrivateKey       string `yaml:"PrivateKey,omitempty"`
	PublicKey        string `yaml:"PublicKey,omitempty"`
}

// profile A.
const (
	profileAMacKeyLen = 32 // octets
	profileAEncKeyLen = 16 // octets
	profileAIcbLen    = 16 // octets
	profileAMacLen    = 8  // octets
	profileAHashLen   = 32 // octets
)

// profile B.
const (
	profileBMacKeyLen = 32 // octets
	profileBEncKeyLen = 16 // octets
	profileBIcbLen    = 16 // octets
	profileBMacLen    = 8  // octets
	profileBHashLen   = 32 // octets
)

func compressKey(uncompressed []byte, y *big.Int) []byte {
	compressed := uncompressed[0:33]
	if y.Bit(0) == 1 { // 0x03
		compressed[0] = 0x03
	} else { // 0x02
		compressed[0] = 0x02
	}
	// logger.Util3GPPLog.Debugf("compressed: %x", compressed)
	return compressed
}

// modified from https://stackoverflow.com/questions/46283760/
// how-to-uncompress-a-single-x9-62-compressed-point-on-an-ecdh-p256-curve-in-go.
func uncompressKey(compressedBytes []byte, priv []byte) (*big.Int, *big.Int) {
	// Split the sign byte from the rest
	signByte := uint(compressedBytes[0])
	xBytes := compressedBytes[1:]

	x := new(big.Int).SetBytes(xBytes)
	three := big.NewInt(3)

	// The params for P256
	c := elliptic.P256().Params()

	// The equation is y^2 = x^3 - 3x + b
	// x^3, mod P
	xCubed := new(big.Int).Exp(x, three, c.P)

	// 3x, mod P
	threeX := new(big.Int).Mul(x, three)
	threeX.Mod(threeX, c.P)

	// x^3 - 3x + b mod P
	ySquared := new(big.Int).Sub(xCubed, threeX)
	ySquared.Add(ySquared, c.B)
	ySquared.Mod(ySquared, c.P)

	// find the square root mod P
	y := new(big.Int).ModSqrt(ySquared, c.P)
	if y == nil {
		// If this happens then you're dealing with an invalid point.
		logger.Util3GPPLog.Errorln("uncompressed key with invalid point")
		return nil, nil
	}

	// Finally, check if you have the correct root. If not you want -y mod P
	if y.Bit(0) != signByte&1 {
		y.Neg(y)
		y.Mod(y, c.P)
	}
	// logger.Util3GPPLog.Debugf("xUncom: %x\nyUncon: %x", x, y)
	return x, y
}

func hmacSha256(input, macKey []byte, macLen int) []byte {
	h := hmac.New(sha256.New, macKey)
	if _, err := h.Write(input); err != nil {
		logger.Util3GPPLog.Errorf("HMAC SHA256 error %+v", err)
	}
	macVal := h.Sum(nil)
	macTag := macVal[:macLen]
	// logger.Util3GPPLog.Debugf("macVal: %x\nmacTag: %x", macVal, macTag)
	return macTag
}

func aes128ctr(input, encKey, icb []byte) []byte {
	output := make([]byte, len(input))
	block, err := aes.NewCipher(encKey)
	if err != nil {
		logger.Util3GPPLog.Errorf("AES128 CTR error %+v", err)
	}
	stream := cipher.NewCTR(block, icb)
	stream.XORKeyStream(output, input)
	// logger.Util3GPPLog.Debugf("aes input: %x %x %x\naes output: %x", input, encKey, icb, output)
	return output
}

func ansiX963KDF(sharedKey, publicKey []byte, profileEncKeyLen, profileMacKeyLen, profileHashLen int) []byte {
	var counter uint32 = 0x00000001
	var kdfKey []byte
	kdfRounds := int(math.Ceil(float64(profileEncKeyLen+profileMacKeyLen) / float64(profileHashLen)))
	for i := 1; i <= kdfRounds; i++ {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		// logger.Util3GPPLog.Debugf("counterBytes: %x", counterBytes)
		tmpK := sha256.Sum256(append(append(sharedKey, counterBytes...), publicKey...))
		sliceK := tmpK[:]
		kdfKey = append(kdfKey, sliceK...)
		// logger.Util3GPPLog.Debugf("kdfKey in round %d: %x", i, kdfKey)
		counter++
	}
	return kdfKey
}

func swapNibbles(input []byte) []byte {
	output := make([]byte, len(input))
	for i, b := range input {
		output[i] = bits.RotateLeft8(b, 4)
	}
	return output
}

func calcSchemeResult(decryptPlainText []byte, supiType string) string {
	var schemeResult string
	if supiType == typeIMSI {
		schemeResult = hex.EncodeToString(swapNibbles(decryptPlainText))
		if schemeResult[len(schemeResult)-1] == 'f' {
			schemeResult = schemeResult[:len(schemeResult)-1]
		}
	} else {
		schemeResult = hex.EncodeToString(decryptPlainText)
	}
	return schemeResult
}

func profileA(input, supiType, privateKey string) (string, error) {
	logger.Util3GPPLog.Infoln("suciToSupi Profile A")
	s, hexDecodeErr := hex.DecodeString(input)
	if hexDecodeErr != nil {
		logger.Util3GPPLog.Errorln("hex DecodeString error")
		return "", hexDecodeErr
	}

	// for X25519(profile A), q (The number of elements in the field Fq) = 2^255 - 19
	// len(pubkey) is therefore ceil((log2q)/8+1) = 32octets
	ProfileAPubKeyLen := 32
	if len(s) < ProfileAPubKeyLen+profileAMacLen {
		logger.Util3GPPLog.Errorln("len of input data is too short")
		return "", fmt.Errorf("suci input too short")
	}

	decryptMac := s[len(s)-profileAMacLen:]
	decryptPublicKey := s[:ProfileAPubKeyLen]
	decryptCipherText := s[ProfileAPubKeyLen : len(s)-profileAMacLen]
	// logger.Util3GPPLog.Debugf("dePub: %x deCiph: %x deMac: %x", decryptPublicKey, decryptCipherText, decryptMac)

	// test data from TS33.501 Annex C.4
	// aHNPriv, _ := hex.DecodeString("c53c2208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d")
	var aHNPriv []byte
	if aHNPrivTmp, err := hex.DecodeString(privateKey); err != nil {
		logger.Util3GPPLog.Errorf("decode error: %+v", err)
	} else {
		aHNPriv = aHNPrivTmp
	}
	var decryptSharedKey []byte
	if decryptSharedKeyTmp, err := curve25519.X25519(aHNPriv, decryptPublicKey); err != nil {
		logger.Util3GPPLog.Errorf("X25519 error: %+v", err)
	} else {
		decryptSharedKey = decryptSharedKeyTmp
	}
	// logger.Util3GPPLog.Debugf("deShared: %x", decryptSharedKey)

	kdfKey := ansiX963KDF(decryptSharedKey, decryptPublicKey, profileAEncKeyLen, profileAMacKeyLen, profileAHashLen)
	decryptEncKey := kdfKey[:profileAEncKeyLen]
	decryptIcb := kdfKey[profileAEncKeyLen : profileAEncKeyLen+profileAIcbLen]
	decryptMacKey := kdfKey[len(kdfKey)-profileAMacKeyLen:]
	// logger.Util3GPPLog.Debugf("deEncKey(size%d): %x deMacKey: %x deIcb: %x", len(decryptEncKey), decryptEncKey, decryptMacKey,
	// decryptIcb)

	decryptMacTag := hmacSha256(decryptCipherText, decryptMacKey, profileAMacLen)
	if bytes.Equal(decryptMacTag, decryptMac) {
		logger.Util3GPPLog.Infoln("decryption MAC match")
	} else {
		logger.Util3GPPLog.Errorln("decryption MAC failed")
		return "", fmt.Errorf("decryption MAC failed")
	}

	decryptPlainText := aes128ctr(decryptCipherText, decryptEncKey, decryptIcb)

	return calcSchemeResult(decryptPlainText, supiType), nil
}

func profileB(input, supiType, privateKey string) (string, error) {
	logger.Util3GPPLog.Infoln("suciToSupi Profile B")
	s, hexDecodeErr := hex.DecodeString(input)
	if hexDecodeErr != nil {
		logger.Util3GPPLog.Errorln("hex DecodeString error")
		return "", hexDecodeErr
	}

	var ProfileBPubKeyLen int // p256, module q = 2^256 - 2^224 + 2^192 + 2^96 - 1
	var uncompressed bool
	switch s[0] {
	case 0x02, 0x03:
		ProfileBPubKeyLen = 33 // ceil(log(2, q)/8) + 1 = 33
		uncompressed = false
	case 0x04:
		ProfileBPubKeyLen = 65 // 2*ceil(log(2, q)/8) + 1 = 65
		uncompressed = true
	default:
		logger.Util3GPPLog.Errorln("input error")
		return "", fmt.Errorf("suci input error")
	}

	// logger.Util3GPPLog.Debugf("len:%d %d", len(s), ProfileBPubKeyLen + ProfileBMacLen)
	if len(s) < ProfileBPubKeyLen+profileBMacLen {
		logger.Util3GPPLog.Errorln("len of input data is too short")
		return "", fmt.Errorf("suci input too short")
	}
	decryptPublicKey := s[:ProfileBPubKeyLen]
	decryptMac := s[len(s)-profileBMacLen:]
	decryptCipherText := s[ProfileBPubKeyLen : len(s)-profileBMacLen]
	// logger.Util3GPPLog.Debugf("dePub: %x deCiph: %x deMac: %x", decryptPublicKey, decryptCipherText, decryptMac)

	// test data from TS33.501 Annex C.4
	// bHNPriv, _ := hex.DecodeString("F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA")
	var bHNPriv []byte
	if bHNPrivTmp, err := hex.DecodeString(privateKey); err != nil {
		logger.Util3GPPLog.Errorf("decode error: %+v", err)
	} else {
		bHNPriv = bHNPrivTmp
	}

	var xUncompressed, yUncompressed *big.Int
	if uncompressed {
		xUncompressed = new(big.Int).SetBytes(decryptPublicKey[1:(ProfileBPubKeyLen/2 + 1)])
		yUncompressed = new(big.Int).SetBytes(decryptPublicKey[(ProfileBPubKeyLen/2 + 1):])
	} else {
		xUncompressed, yUncompressed = uncompressKey(decryptPublicKey, bHNPriv)
		if xUncompressed == nil || yUncompressed == nil {
			logger.Util3GPPLog.Errorln("uncompressed key has invalid point")
			return "", fmt.Errorf("key uncompression error")
		}
	}
	// logger.Util3GPPLog.Debugf("xUncom: %x yUncom: %x", xUncompressed, yUncompressed)

	// x-coordinate is the shared key
	decryptSharedKey, _ := elliptic.P256().ScalarMult(xUncompressed, yUncompressed, bHNPriv)
	// logger.Util3GPPLog.Debugf("deShared: %x", decryptSharedKey.Bytes())

	decryptPublicKeyForKDF := decryptPublicKey
	if uncompressed {
		decryptPublicKeyForKDF = compressKey(decryptPublicKey, yUncompressed)
	}

	kdfKey := ansiX963KDF(decryptSharedKey.Bytes(), decryptPublicKeyForKDF, profileBEncKeyLen, profileBMacKeyLen,
		profileBHashLen)
	// logger.Util3GPPLog.Debugf("kdfKey: %x", kdfKey)
	decryptEncKey := kdfKey[:profileBEncKeyLen]
	decryptIcb := kdfKey[profileBEncKeyLen : profileBEncKeyLen+profileBIcbLen]
	decryptMacKey := kdfKey[len(kdfKey)-profileBMacKeyLen:]
	// logger.Util3GPPLog.Debugf("deEncKey(size%d): %x deMacKey: %x deIcb: %x", len(decryptEncKey), decryptEncKey, decryptMacKey,
	// decryptIcb)

	decryptMacTag := hmacSha256(decryptCipherText, decryptMacKey, profileBMacLen)
	if bytes.Equal(decryptMacTag, decryptMac) {
		logger.Util3GPPLog.Infoln("decryption MAC match")
	} else {
		logger.Util3GPPLog.Errorln("decryption MAC failed")
		return "", fmt.Errorf("decryption MAC failed")
	}

	decryptPlainText := aes128ctr(decryptCipherText, decryptEncKey, decryptIcb)

	return calcSchemeResult(decryptPlainText, supiType), nil
}

// suci-0(SUPI type)-mcc-mnc-routingIndentifier-protectionScheme-homeNetworkPublicKeyIdentifier-schemeOutput.
const (
	supiTypePlace      = 1
	mccPlace           = 2
	mncPlace           = 3
	schemePlace        = 5
	hNPublicKeyIDPlace = 6
)

const (
	typeIMSI       = "0"
	imsiPrefix     = "imsi-"
	nullScheme     = "0"
	profileAScheme = "1"
	profileBScheme = "2"
)

func ToSupi(suci string, suciProfiles []SuciProfile) (string, error) {
	suciPart := strings.Split(suci, "-")
	logger.Util3GPPLog.Infof("suciPart: %+v", suciPart)

	suciPrefix := suciPart[0]
	switch suciPrefix {
	case "imsi", "nai":
		logger.Util3GPPLog.Infoln("got supi")
		return suci, nil
	case "suci":
		if len(suciPart) < 6 {
			return "", fmt.Errorf("suci with wrong format")
		}
	default:
		return "", fmt.Errorf("unknown suciPrefix [%s]", suciPrefix)
	}

	logger.Util3GPPLog.Infof("scheme %s", suciPart[schemePlace])
	scheme := suciPart[schemePlace]
	mccMnc := suciPart[mccPlace] + suciPart[mncPlace]

	supiPrefix := imsiPrefix
	if suciPrefix == "suci" && suciPart[supiTypePlace] == typeIMSI {
		supiPrefix = imsiPrefix
		logger.Util3GPPLog.Infoln("supi type is IMSI")
	}

	if scheme == nullScheme { // NULL scheme
		return supiPrefix + mccMnc + suciPart[len(suciPart)-1], nil
	}

	// (HNPublicKeyID-1) is the index of "suciProfiles" slices
	keyIndex, err := strconv.Atoi(suciPart[hNPublicKeyIDPlace])
	if err != nil {
		return "", fmt.Errorf("parse HNPublicKeyID error: %+v", err)
	}
	if keyIndex > len(suciProfiles) {
		return "", fmt.Errorf("keyIndex(%d) out of range(%d)", keyIndex, len(suciProfiles))
	}

	protectScheme := suciProfiles[keyIndex-1].ProtectionScheme
	privateKey := suciProfiles[keyIndex-1].PrivateKey

	if scheme != protectScheme {
		return "", fmt.Errorf("protect Scheme mismatch [%s:%s]", scheme, protectScheme)
	}

	switch scheme {
	case profileAScheme:
		if profileAResult, err := profileA(suciPart[len(suciPart)-1], suciPart[supiTypePlace], privateKey); err != nil {
			return "", err
		} else {
			return supiPrefix + mccMnc + profileAResult, nil
		}
	case profileBScheme:
		if profileBResult, err := profileB(suciPart[len(suciPart)-1], suciPart[supiTypePlace], privateKey); err != nil {
			return "", err
		} else {
			return supiPrefix + mccMnc + profileBResult, nil
		}
	default:
		return "", fmt.Errorf("protect Scheme (%s) is not supported", scheme)
	}
}
