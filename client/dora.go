// All credits to the impeccable code at:
// github.com/insomniacslk/exdhcp
// github.com/insomniacslk/dhcp

package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"sort"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)


// Parts of the DHCPv4 packet required for address acquisition
type DHCPv4 struct {
	// https://www.rfc-editor.org/rfc/rfc2131#page-37
	op        uint8 //opcode, included in all requests
	htype     uint16 // hardware type, included in all requests
	xid       uint32 // transaction id, included in all requests
	yiaddr    net.IP // your address (from server), obtained from response and included in subsequent requests
	chaddr    net.HardwareAddr // client hardware address, included in all requests
	options   map[uint8][]uint8 // dhcp options, see https://www.rfc-editor.org/rfc/rfc2132
}


var (
	// Addresses we use
	ServerIP = net.IPv4bcast
	ClientIP = net.IPv4zero

	// DHCPv4 magic cookie
	DhcpMagic = [4]uint8{99, 130, 83, 99}
)


const (
	// DHCP ports
	ServerPort = 67
	ClientPort = 68

	// IPv4 UDP protocol identifier
	ProtocolUdp = 17

	// Arbitrary maximum supported UDP packet size, same as that in insomniacslk/dhcp
	MaxUdpLen = 8192

	// Minimum length of BOOTP packet
	MinDhcpLen = 300

	// DHCP message types we use
	MessageTypeNone uint8 = 0
	MessageTypeDiscover uint8 = 1
	MessageTypeOffer uint8 = 2
	MessageTypeRequest uint8 = 3
	MessageTypeDecline uint8 = 4
	MessageTypeAck uint8 = 5
	MessageTypeNak uint8 = 6
	MessageTypeRelease uint8 = 7
	MessageTypeInform uint8 = 8

	// DHCP hardware types we use
	HWTypeEthernet = 1

	// DHCP options we use
	OptionPad uint8 = 0
	OptionDomainName uint8 = 15
	OptionRequestedIPAddress uint8 = 50
	OptionDHCPMessageType uint8 = 53 // Marks start of DHCP message type singleton
	OptionServerIdentifier uint8 = 54
	OptionParameterRequestList uint8 = 55 // Marks start of list of requested DHCP params
	OptionAgentInfo uint8 = 82 // Not directly used but has special rules
	OptionEnd uint8 = 255 // Always the last option

	// Message type
	OpcodeBootRequest uint8 = 1
	OpcodeBootReply uint8 = 2

	// Zero constants used for clarity
	NoHops = 0
	NoSecs = 0
	NoFlags = 0
	NoAddr = 0
	NoChecksum = 0

	// Implementation defaults
	NetworkTimeout = 3 * time.Second
)


// Commandline flags
var ifname = flag.String("dev", "lo", "What network device to send requests to")

// Read commandline flags and perform a DORA sequence
func main() {
	log.SetFlags(0)
	flag.Parse()
	err := dora(*ifname)
	if err != nil {
		log.Fatal(err)
	}
}

// Perform a DORA sequence using the network device with name ifname
// and package-global client- and server addresses:
//
// - send a discovery-request
//
// - listen for an offer-response
//
// - send a request-request
//
// - listen for an acknowledgement-response
func dora(ifname string) error {
	// Make send socket
	sfd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW) // Raw IP packets
	if err != nil {
		return err
	}
	err = unix.SetsockoptInt(sfd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) // Make ports instantly re-available after close
	if err != nil {
		return err
	}
	err = unix.SetsockoptInt(sfd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1) // IP Header is included with data
	if err != nil {
		return err
	}
	err = unix.BindToDevice(sfd, ifname)
	if err != nil {
		return err
	}
	err = unix.SetsockoptInt(sfd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1) // Allow use of broadcast address
	if err != nil {
		return err
	}

	// Make receive socket
	rfd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, int(htons(unix.ETH_P_IP))) // Receive IP packets
	if err != nil {
		return err
	}
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	llAddr := unix.SockaddrLinklayer{
		Ifindex: iface.Index,
		Protocol: htons(unix.ETH_P_IP),
	}
	err = unix.Bind(rfd, &llAddr)
	if err != nil {
		return err
	}

	defer func() {
		// close the sockets
		if err := unix.Close(sfd); err != nil {
			log.Printf("unix.Close(sendFd) failed: %v", err)
		}
		if sfd != rfd {
			if err := unix.Close(rfd); err != nil {
				log.Printf("unix.Close(recvFd) failed: %v", err)
			}
		}
	}()

	transactionID := rand.Uint32()


	// Make discovery payload
	discovery := DHCPv4{
		op: OpcodeBootRequest,
		htype: HWTypeEthernet,
		xid: transactionID,
		yiaddr: net.IPv4zero,
		chaddr: iface.HardwareAddr,
		options: map[uint8][]uint8{
			OptionDHCPMessageType: []uint8{MessageTypeDiscover},
			OptionParameterRequestList: []uint8{OptionDomainName},
			OptionEnd: []uint8{},
		},
	}

	log.Printf("discovery request")
	offer, err := send(sfd, rfd, &discovery, MessageTypeDiscover)
	if err != nil {
		return err
	}
	log.Printf("offer response")


	// Make request payload
	request := DHCPv4{
		op: OpcodeBootRequest,
		htype: HWTypeEthernet,
		xid: transactionID,
		yiaddr: net.IPv4zero,
		chaddr: iface.HardwareAddr,
		options: map[uint8][]uint8{
			OptionDHCPMessageType: []uint8{MessageTypeDiscover},
			OptionParameterRequestList: []uint8{OptionDomainName},
			OptionRequestedIPAddress: []uint8{offer.yiaddr[0], offer.yiaddr[1], offer.yiaddr[2], offer.yiaddr[3]},
		},
	}

	serverIP := offer.options[OptionServerIdentifier]
	if serverIP != nil {
		request.options[OptionServerIdentifier] = []uint8{serverIP[0], serverIP[1],  serverIP[2], serverIP[3]}
	}

	log.Printf("request request")
	acknowledge, err := send(sfd, rfd, &request, MessageTypeRequest)
	if err != nil {
		return err
	}
	log.Printf("acknowledge response")
	log.Println(acknowledge.yiaddr)

	return nil
}


// Make a raw IP datagram with dhcp4 as udp body and write it to the raw socket
// sfd (send socket), then wait for responses arriving at the raw socket rfd
// (receive socket). Returns a new DHCPv4 struct made from the response.
func send(sfd int, rfd int, dhcp4 *DHCPv4, messageType uint8) (*DHCPv4, error) {
	log.Printf("send()")
	udpdata := dhcp4.serialize()
	udpheader := make([]uint8, 8)
	binary.BigEndian.PutUint16(udpheader[:2], uint16(ClientPort))
	binary.BigEndian.PutUint16(udpheader[2:4], uint16(ServerPort))
	binary.BigEndian.PutUint16(udpheader[4:6], uint16(8+len(udpdata)))
	binary.BigEndian.PutUint16(udpheader[6:8], uint16(NoChecksum))

	h := ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: 20 + len(udpheader) + len(udpdata),
		TTL:      64,
		Protocol: ProtocolUdp,
		Dst:      ServerIP,
		Src:      ClientIP,
	}
	datagram, err := h.Marshal()
	if err != nil {
		return nil, err
	}
	datagram = append(datagram, udpheader...)
	datagram = append(datagram, udpdata...)

	var destination [net.IPv4len]uint8
	copy(destination[:], ServerIP)

	var response *DHCPv4
	remoteAddr := unix.SockaddrInet4{Port: ClientPort, Addr: destination}
	recvErrors := make(chan error, 1)
	go func(errs chan<- error) {
		timeout := unix.NsecToTimeval(NetworkTimeout.Nanoseconds())
		err := unix.SetsockoptTimeval(rfd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)
		if err != nil {
			errs <- err
			return
		}
		for {
			buf := make([]uint8, MaxUdpLen)
			log.Printf("(1) Listening from %v\n", remoteAddr)
			n, _, innerErr := unix.Recvfrom(rfd, buf, 0)
			if innerErr != nil {
				errs <- innerErr
				return
			}
			log.Printf("(2) Listening from %v\n", remoteAddr)
			var iph ipv4.Header
			err := iph.Parse(buf[:n])
			if err != nil {
				continue
			}
			log.Printf("(3) Listening from %v\n", remoteAddr)
			if iph.Protocol != ProtocolUdp {
				continue
			}
			log.Printf("(4) Listening from %v\n", remoteAddr)
			udph := buf[iph.Len:n]
			srcPort := int(binary.BigEndian.Uint16(udph[0:2]))
			_pLen := int(binary.BigEndian.Uint16(udph[4:6]))
			_payload := buf[iph.Len+8 : iph.Len+_pLen]
			log.Printf("(4) srcPort: %v, ServerPort: %v, pLen: %v\n", srcPort, ServerPort, _pLen)
			_response, err := deserialize(_payload)
			log.Printf("(4) srcPort: %v, ServerPort: %v, pLen: %v\n", srcPort, ServerPort, _pLen)
			if err != nil {
				log.Printf("Unexpected")
				errs <- err
				return
			}
			log.Printf("(4) opcode: %v\n", _response.op)
			if srcPort != ServerPort {
				continue
			}
			log.Printf("(5) Listening from %v\n", remoteAddr)
			dstPort := int(binary.BigEndian.Uint16(udph[2:4]))
			if dstPort != ClientPort {
				continue
			}
			log.Printf("(6) Listening from %v\n", remoteAddr)
			pLen := int(binary.BigEndian.Uint16(udph[4:6]))
			payload := buf[iph.Len+8 : iph.Len+pLen]
			log.Println("Received some data")
			response, err = deserialize(payload)
			if err != nil {
				errs <- err
				return
			}
			log.Printf("(7) Listening from %v\n", remoteAddr)
			if response.xid != dhcp4.xid {
				continue
			}
			log.Printf("(8) Listening from %v\n", remoteAddr)
			if response.op != OpcodeBootReply {
				continue
			}
			log.Printf("(9) Listening from %v\n", remoteAddr)
			if messageType == MessageTypeNone {
				break
			}
			log.Printf("(10) Listening from %v\n", remoteAddr)
			if len(response.options[OptionDHCPMessageType]) != 1 {
				fmt.Errorf("malformed DHCP packet: invalid message type")
			}
			log.Printf("(11) Listening from %v\n", remoteAddr)
			if response.options[OptionDHCPMessageType][0] == messageType {
				break
			}
			log.Printf("(12) Listening from %v\n", remoteAddr)
		}
		errs <- nil
	}(recvErrors)

	err = unix.Sendto(sfd, datagram, 0, &remoteAddr)
	if err != nil {
		return nil, err
	}

	select {
	case err = <- recvErrors:
		if err == unix.EAGAIN {
			return nil, fmt.Errorf("timed out while listening for replies")
		}
		if err != nil {
			return nil, err
		}
	case <-time.After(NetworkTimeout):
		return nil, fmt.Errorf("timed out while listening for replies")
	}
	return response, nil
}


// Turns a raw udp body (buf) into a DHCPv4 struct.
func deserialize(buf []uint8) (*DHCPv4, error) {
	log.Println(buf)
	// https://www.rfc-editor.org/rfc/rfc2131#page-37
	if len(buf) < 240 {
		return nil, fmt.Errorf("malformed DHCP packet: size less than 240")
	}
	var dhcp4 DHCPv4
	dhcp4.op = buf[0]
	dhcp4.htype = uint16(buf[1])
	hwAddrLen := buf[2]
	log.Printf("(1) Deserialize")
	// hops = buf[3] (skip)
	dhcp4.xid = binary.BigEndian.Uint32(buf[4:8])
	// secs = binary.BigEndian.Uint16(buf[8:10]) (skip)
	// flags = binary.BigEndian.Uint16(buf[10:12]) (skip)
	// ciaddr = copy(buf[12:16]) (skip)
	dhcp4.yiaddr = []uint8{buf[16], buf[17], buf[18], buf[19]}
	// siaddr = copy(buf[20:24]) (skip)
	// giaddr = copy(buf[24:28]) (skip)

	if hwAddrLen > 16 {
		hwAddrLen = 16
	}
	dhcp4.chaddr = make(net.HardwareAddr, 16)
	copy(dhcp4.chaddr, buf[28:44])
	dhcp4.chaddr = dhcp4.chaddr[:hwAddrLen]

	// sname = copy(buf[44:108]) (skip)
	// file = copy(buf[108:236]) (skip)

	log.Printf("(2) Deserialize")
	var magic [4]byte
	copy(magic[:], buf[236:240])
	if magic != DhcpMagic {
		log.Printf("(3) Deserialize")
		return nil, fmt.Errorf("malformed DHCP packet: got magic cookie %v, want %v", magic[:], DhcpMagic[:])
	}

	log.Printf("(4) Deserialize")
	dhcp4.options = make(map[uint8][]uint8)
	optionsbuf := buf[240:]
	end := false
	for len(optionsbuf) >= 1 {
		code := optionsbuf[0]
		if code == OptionPad {
			continue
		} else if code == OptionEnd {
			end = true
			break
		}
		length := int(optionsbuf[1])
		optionsbuf = optionsbuf[2:]
		if len(optionsbuf) < length {
			return nil, fmt.Errorf("malformed DHCP packet: bad option length")
		}
		dhcp4.options[code] = append(dhcp4.options[code], optionsbuf[:length:length]...)
		optionsbuf = optionsbuf[length:]
	}
	if !end {
		return nil, io.ErrUnexpectedEOF
	}

	return &dhcp4, nil
}


// Turns a DHCPv4 struct into a raw udp body
func (dhcp4 *DHCPv4) serialize() []uint8 {
	// https://www.rfc-editor.org/rfc/rfc2131#page-37
	buf := make([]uint8, 0, MinDhcpLen)
	buf = append(buf, dhcp4.op)
	buf = append(buf, uint8(dhcp4.htype))
	buf = append(buf, uint8(len(dhcp4.chaddr)))
	buf = append(buf, uint8(NoHops))
	buf = binary.BigEndian.AppendUint32(buf, dhcp4.xid)
	buf = binary.BigEndian.AppendUint16(buf, NoSecs)
	buf = binary.BigEndian.AppendUint16(buf, NoFlags)
	buf = binary.BigEndian.AppendUint32(buf, NoAddr) // ciaddr
	buf = append(buf, make([]uint8, 4)...) // yiaddr
	ip := dhcp4.yiaddr.To4()
	log.Println(ip)
	copy(buf[len(buf)-4:], ip[:4])
	buf = binary.BigEndian.AppendUint32(buf, NoAddr) // siaddr
	buf = binary.BigEndian.AppendUint32(buf, NoAddr) // giaddr
	buf = append(buf, make([]uint8, 16)...) // chaddr
	copy(buf[len(buf)-16:], dhcp4.chaddr)
	buf = append(buf, make([]uint8, 64)...) // sname
	buf = append(buf, make([]uint8, 128)...) // file
	buf = append(buf, DhcpMagic[:]...)
	buf = appendOptions(buf, dhcp4.options)


	if len(buf) < MinDhcpLen {
		buf = append(buf, bytes.Repeat([]uint8{OptionPad}, MinDhcpLen-len(buf))...)
	}

	log.Println(buf)
	return buf
}


// Turns a DHCPv4.Options map to a raw dhcp options list and append to buf
func appendOptions(buf []uint8, options map[uint8][]uint8) []uint8 {
	var hasOptionAgentInfo, hasOptionEnd bool
	var sortedOptions []int
	for option := range options {
		if option == OptionAgentInfo {
			hasOptionAgentInfo = true
			continue
		}
		if option == OptionEnd {
			hasOptionEnd = true
			continue
		}
		sortedOptions = append(sortedOptions, int(option))
	}
	sort.Ints(sortedOptions)
	if hasOptionAgentInfo {
		sortedOptions = append(sortedOptions, int(OptionAgentInfo))
	}
	if hasOptionEnd {
		sortedOptions = append(sortedOptions, int(OptionEnd))
	}

	for _, option := range sortedOptions {
		code := uint8(option)
		if code == OptionEnd || code == OptionPad {
			continue
		}

		data := options[code]

		// Ensure even 0-length options are written out
		if len(data) == 0 {
			buf = append(buf, code)
			buf = append(buf, 0)
		}
		// RFC 3396: If more than 256 bytes of data are given, the
		// option is simply listed multiple times.
		for len(data) > 0 {
			buf = append(buf, code)
			n := len(data)
			if n > math.MaxUint8 {
				n = math.MaxUint8
			}
			buf = append(buf, uint8(n))
			buf = append(buf, data[:n]...)
			data = data[n:]
		}
	}
	return buf
}


// Host to network byte order
func htons(v uint16) uint16 {
	var tmp [2]uint8
	binary.BigEndian.PutUint16(tmp[:], v)
	return binary.LittleEndian.Uint16(tmp[:])
}
