package spa

import (
	"crypto/md5"
	"fmt"
	"github.com/1uLang/libspb/encrypt"
	"github.com/pkg/errors"
	"net"
	"time"
)

const (
	startCode          = 0x2323
	packetVersion      = 0x01
	packetLength       = 80
	packetHeaderLength = 4
	packetSignLength   = 16
	packetBodyLength   = 60

	timestampFieldSize      = 8  // Unix Timestamp - 64 bit = 8 bytes
	nonceFieldSize          = 4  // bytes - according to the OpenSPA protocol
	clientDeviceIdFieldSize = 16 // Client Device ID - 128 bits = 16 bytes
	clientPublicIPFieldSize = 16 // Client Public IP - 128 bits = 16 bytes - could be IPv4 or IPv6
	serverPublicIPFieldSize = 16 // Server Public IP - 128 bit = 16 bytes - could be IPv4 or IPv6
)

var (
	InvalidStartCodePacket = errors.New("invalid packet (packet start code is error)")
	InvalidMethodPacket    = errors.New("invalid packet (packet method is not support)")
	InvalidSignPacket      = errors.New("invalid packet (packet sign is error)")
	InvalidBodyPacket      = errors.New("invalid packet (body packet length is error)")
	VersionLowPacket       = errors.New("version low packet")
)

// spa packet struct:
// 0               |   1           |       2       |           3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   START  CODE[0x2323]         | VERSION[0x01] | METHOD[0x01]  | [HEADER]
// |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
// +                                                               +
// |                        MD5 SUM			                       | [SIGN]
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Timestamp                              | [ BODY ]
// +                                                               +
// |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
// |                        Nonce                  				   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// +                                                               +
// |                        Client Device ID                       |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                        Client Public IP                       +
// |                                                               |
// +                                                               +
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                        Server Public IP                       +
// |                                                               |
// +                                                               +
// +-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type Body struct {
	ClientDeviceId string
	ClientPublicIP net.IP
	ServerPublicIP net.IP
}
type requestBody struct {
	Timestamp uint64
	Nonce     Nonce
	Body
}

// NewPacket 生成spa报
func NewPacket(body *Body, method encrypt.MethodInterface) ([]byte, error) {
	packet := encodeHeader(packetVersion, method)
	bytes, err := body.Encrypt(method)
	if err != nil {
		return nil, errors.New("body encode failed:" + err.Error())
	}
	packet = append(packet, bytes...)
	return packet, nil
}

// ParsePacket 解析spa报
func ParsePacket(data []byte) (body *Body, err error) {

	offset := 0
	if !checkStartCode(data) {
		return nil, InvalidStartCodePacket
	}

	version, method := decodeHeader(data)

	if version != packetVersion {
		return nil, VersionLowPacket
	}
	offset += packetHeaderLength

	c, err := encrypt.GetMethodInstance(method)
	if err != nil {
		return nil, InvalidMethodPacket
	}

	md5sum := make([]byte, packetSignLength)
	copy(md5sum, data[offset:offset+packetSignLength])
	offset += packetSignLength

	bodyBytes, err := c.Decrypt(data[offset:])
	if err != nil {
		return nil, errors.New("body decrypt failed:" + err.Error())
	}
	//md5
	if fmt.Sprintf("%x", md5.Sum(bodyBytes)) != fmt.Sprintf("%x", md5sum) {
		return nil, InvalidSignPacket
	}
	b, err := bodyDecode(bodyBytes)
	if err != nil {
		return nil, errors.New("body decode failed:" + err.Error())
	}
	return &b.Body, nil
}

func encodeHeader(version byte, method encrypt.MethodInterface) []byte {
	header := make([]byte, packetHeaderLength)
	header[0] = byte(startCode & 0x00ff)
	header[1] = byte(startCode >> 8)
	header[2] = version
	header[3] = method.Method()
	return header
}

func decodeHeader(data []byte) (version, method uint8) {
	version = data[2]
	method = data[3]
	return
}

func (body *Body) encode() ([]byte, error) {
	// This is our packet payload
	buffer := make([]byte, packetBodyLength)

	offset := 0 // we initialize the offset to 0
	// Unix Timestamp
	timestampBin := timestampEncode(uint64(time.Now().Unix()))
	for i := 0; i < timestampFieldSize; i++ {
		buffer[offset+i] = timestampBin[i]
	}
	offset += timestampFieldSize

	// Nonce
	nonce, err := RandomNonce()
	if err != nil {
		return nil, errors.New("random nonce failed:" + err.Error())
	}
	for i := 0; i < nonceFieldSize; i++ {
		buffer[offset+i] = nonce[i]
	}
	offset += nonceFieldSize

	// Client Device ID
	clientDeviceId, err := clientDeviceIdEncode(body.ClientDeviceId)
	if err != nil {
		return nil, errors.Wrap(err, "client device id encoding")
	}
	for i := 0; i < clientDeviceIdFieldSize; i++ {
		buffer[offset+i] = clientDeviceId[i]
	}
	offset += clientDeviceIdFieldSize

	// Client Public IP
	clientPublicIP, err := ipAddressToBinIP(body.ClientPublicIP)
	if err != nil {
		return nil, errors.Wrap(err, "client public ip to bin")
	}
	for i := 0; i < clientPublicIPFieldSize; i++ {
		buffer[offset+i] = clientPublicIP[i]
	}
	offset += clientPublicIPFieldSize

	// Server Public IP
	serverPublicIP, err := ipAddressToBinIP(body.ServerPublicIP)
	if err != nil {
		return nil, err
	}
	for i := 0; i < serverPublicIPFieldSize; i++ {
		buffer[offset+i] = serverPublicIP[i]
	}
	offset += serverPublicIPFieldSize

	return buffer, nil
}

func bodyDecode(data []byte) (body *requestBody, err error) {
	if len(data) < packetBodyLength {
		return nil, InvalidBodyPacket
	}
	body = new(requestBody)
	offset := 0 // we initialize the offset to 0
	body.Timestamp, err = timestampDecode(data[:timestampFieldSize])
	if err != nil {
		return nil, errors.New("decode timestamp failed:" + err.Error())
	}
	offset += timestampFieldSize

	copy(body.Nonce, data[offset:offset+nonceFieldSize])
	offset += nonceFieldSize

	body.ClientDeviceId, err = clientDeviceIdDecode(data[offset : offset+clientDeviceIdFieldSize])
	if err != nil {
		return nil, errors.New("decode client device id failed:" + err.Error())
	}
	offset += clientDeviceIdFieldSize

	body.ClientPublicIP, err = binIPAddressToIP(data[offset : offset+clientPublicIPFieldSize])
	offset += clientPublicIPFieldSize

	body.ServerPublicIP, err = binIPAddressToIP(data[offset : offset+serverPublicIPFieldSize])
	offset += serverPublicIPFieldSize
	return
}

func (body *Body) Encrypt(c encrypt.MethodInterface) ([]byte, error) {

	bodyEncodes, err := body.encode()
	if err != nil {
		return nil, errors.New("bode encode failed:" + err.Error())
	}

	md5sum := md5.Sum(bodyEncodes)
	bytes := make([]byte, packetSignLength)
	for k, v := range md5sum {
		bytes[k] = v
	}
	bEncrypt, err := c.Encrypt(bodyEncodes)
	if err != nil {
		return nil, errors.New("bode encrypt failed:" + err.Error())
	}
	bytes = append(bytes, bEncrypt...)
	return bytes, nil
}

// 检测报的起始报文是否有效
func checkStartCode(data []byte) bool {
	startC := uint16(data[0]) + uint16(data[1])<<8
	return startC == startCode
}
