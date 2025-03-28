// All credits to the impeccable code at:
// github.com/insomniacslk/exdhcp
// github.com/insomniacslk/dhcp

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"math"
	"math/rand"
	"net"
	"sort"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// All parts of the DHCPv4 packet we use
type DHCPv4 struct {
	OpCode         uint8
	HWType         uint16
	TransactionID  uint32
	ClientHWAddr   net.HardwareAddr
	Options        map[uint8][]uint8
}


var (
	// Addresses we use
	ServerIP = net.IPv4bcast
	ClientIP = net.IPv4zero

	// DHCPv4 magic cookie
	magicCookie = [4]uint8{99, 130, 83, 99}
)


const (
	// DHCP ports
	ServerPort = 67
	ClientPort = 68

	// IPv4 UDP protocol identifier
	ProtocolUDP = 17

	// Arbitrary maximum supported UDP packet size, same as that in insomniacslk/dhcp
	MaxUDPReceivedPacketSize = 8192

	// Minimum length of BOOTP packet
	MinBootpLen = 300

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
	OptionDomainName uint8 = 15 //
	OptionDHCPMessageType uint8 = 53 // Marks start of DHCP message type singleton
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
		OpCode: OpcodeBootRequest,
		HWType: HWTypeEthernet,
		TransactionID: transactionID,
		ClientHWAddr: iface.HardwareAddr,
		Options: map[uint8][]uint8{
			OptionDHCPMessageType: []uint8{MessageTypeDiscover},
			OptionParameterRequestList: []uint8{OptionDomainName},
			OptionEnd: []uint8{},
		},
	}

	offer, err := send(sfd, rfd, &discovery, MessageTypeDiscover)
	if err != nil {
		return err
	}

	// Make request payload
	request := DHCPv4{
		OpCode: OpcodeBootRequest,
		HWType: HWTypeEthernet,
		TransactionID: transactionID,
		ClientHWAddr: iface.HardwareAddr,
		Options: map[uint8][]uint8{

		},
	}

	acknowledge, err := send(sfd, rfd, &request, MessageTypeRequest)
	if err != nil {
		return err
	}

	return nil
}


func send(sfd int, rfd int, dhcp4 *DHCPv4, messageType uint8) (*DHCPv4, error) {
	udpdata := dhcp4.Marshal()
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
		Protocol: ProtocolUDP,
		Dst:      ServerIP,
		Src:      ClientIP,
	}
	datagram, err := h.Marshal()
	if err != nil {
		return nil, err
	}
	datagram = append(datagram, udpheader)
	datagram = append(datagram, udpdata)

	var (
		destination [net.IPv4len]uint8
		response *DHCPv4
	)
	copy(destination[:], raddr.IP.To4())
	remoteAddr := unix.SockaddrInet4{Port: ClientPort, Addr: destination}
	recvErrors := make(chan error, 1)
	go func(errs chan<- error) {
		timeout := unix.NsecToTimeval(NetworkTimeout.Nanoseconds())
		err := unix.SetsockoptTimeval(recvFd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout)
		if err != nil {
			errs <- err
			return
		}
		for {
			buf := make([]uint8, MaxUDPReceivedPacketSize)
			n, _, innerErr := unix.Recvfrom(rfd, buf, 0)
			if innerErr != nil {
				errs <- innerErr
				return
			}
			var iph ipv4.Header
			err := iph.Parse(buf[:n])
			if err != nil {
				continue
			}
			if iph.Protocol != ProtocolUDP {
				continue
			}
			udph := buf[iph.Len:n]
			srcPort := int(binary.BigEndian.Uint16(udph[0:2]))
			if srcPort != ServerPort {
				continue
			}
			dstPort := int(binary.BigEndian.Uint16(udph[2:4]))
			if dstPort != ClientPort {
				continue
			}
			pLen := int(binary.BigEndian.Uint16(udph[2:4]))
			payload := buf[iph.Len+8 : iph.Len+pLen]
			response, err = parse(payload)
			if err != nil {
				errs <- err
				return
			}
			if response.TransactionID != dhcp4.TransactionID {
				continue
			}
			if response.OpCode != OpcodeBootReply {
				continue
			}
			if messageType == MessageTypeNone {
				break
			}
			if response.messageType() == messageType {
				break
			}
		}
		errs <- nil
	}(recvErrors)

	err = unix.SendTo(sfd, datagram, 0, &remoteAddr)
	if err != nil {
		return nil, err
	}

	select {
	case err = <- recvErrors:
		if err == unix.EAGAIN {
			return nil, errors.New("timed out while listening for replies")
		}
		if err != nil {
			return nil, err
		}
	case <-time.After(NetworkTimeout):
		return nil, errors.New("timed out while listening for replies")
	}
	return response, nil
}


func (dhcp4 *DHCPv4) Marshal() []uint8 {
	// https://www.rfc-editor.org/rfc/rfc2131#page-37
	buf := make([]uint8, 0, MinBootpLen)
	buf = append(buf, dhcp4.OpCode)
	buf = append(buf, uint8(dhcp4.HWType))
	buf = append(buf, uint8(len(dhcp4.ClientHWAddr)))
	buf = append(buf, uint8(NoHops))
	buf = binary.BigEndian.AppendUint32(buf, dhcp4.TransactionID)
	buf = binary.BigEndian.AppendUint16(buf, NoSecs)
	buf = binary.BigEndian.AppendUint16(buf, NoFlags)
	buf = binary.BigEndian.AppendUint32(buf, NoAddr)
	buf = binary.BigEndian.AppendUint32(buf, NoAddr)
	buf = binary.BigEndian.AppendUint32(buf, NoAddr)
	buf = binary.BigEndian.AppendUint32(buf, NoAddr)
	buf = append(buf, make([]uint8, 16)...)
	copy(buf[len(buf)-16:], dhcp4.ClientHWAddr)
	buf = append(buf, make([]uint8, 64)...)
	buf = append(buf, make([]uint8, 128)...)
	buf = append(buf, magicCookie[:]...)
	buf = appendOptions(buf, dhcp4.Options)

	if len(buf) < MinBootpLen {
		buf = append(buf, bytes.Repeat([]uint8{OptionPad}, MinBootpLen-len(buf))...)
	}

	return buf
}

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

func parse(buf []uint8) (*DHCPv4, error) {
	var dhcp4 DHCPv4
	return &dhcp4, nil
}

func htons(v uint16) uint16 {
	var tmp [2]uint8
	binary.BigEndian.PutUint16(tmp[:], v)
	return binary.LittleEndian.Uint16(tmp[:])
}
