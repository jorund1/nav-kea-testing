// All credits to the impeccable code at:
// github.com/insomniacslk/exdhcp
// github.com/insomniacslk/dhcp

package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"math/rand"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

var magicCookie = [4]byte{99, 130, 83, 99}

// DHCPv4 represents a DHCPv4 packet header and options. See the New* functions
// to build DHCPv4 packets.
type DHCPv4 struct {
	OpCode         uint8
	HWType         uint16
	HopCount       uint8
	TransactionID  [4]byte
	NumSeconds     uint16
	Flags          uint16
	ClientIPAddr   net.IP
	YourIPAddr     net.IP
	ServerIPAddr   net.IP
	GatewayIPAddr  net.IP
	ClientHWAddr   net.HardwareAddr
	ServerHostName string
	BootFileName   string
	Options        map[uint8][]byte
}

// DHCP ports
const (
	ServerPort = 67
	ClientPort = 68
)

// DHCP options
const (
	OptionDomainName uint8 = 15
	OptionDHCPMessageType uint8 = 53
	OptionParameterRequestList uint8 = 55
	OptionEnd uint8 = 255
)

// DHCP message types
const (
	MessageTypeNone     byte = 0
	MessageTypeDiscover byte = 1
	MessageTypeOffer    byte = 2
	MessageTypeRequest  byte = 3
	MessageTypeDecline  byte = 4
	MessageTypeAck      byte = 5
	MessageTypeNak      byte = 6
	MessageTypeRelease  byte = 7
	MessageTypeInform   byte = 8
)

const (
	HWTypeEthernet = 1
)

const (
	OpcodeBootRequest uint8 = 1
)

const NoHops = 0
const NoSecs = 0
const NoFlags = 0


func dora(ifname string) error {
	raddr := &net.UDPAddr{IP: net.IPv4bcast, Port: ServerPort}
	laddr := &net.UDPAddr{IP: net.IPv4zero, Port: ClientPort}

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

	// Discover
	minPacketLen := 200
	buf := make([]byte, 0, minPacketLen)
	buf.Write8(uint8(OpcodeBootRequest))
	buf.Write8(uint8(HWTypeEthernet))
	buf.Write8(uint8(len(iface.HardwareAddr)))
	buf.Write8(NoHops)
	buf.Write32(rand.Uint32())
	buf.Write16(NoSecs)
	buf.Write16(NoFlags)
	buf.Write32(0)
	buf.Write32(0)
	buf.Write32(0)
	buf.Write32(0)
	copy(buf.WriteN(16), iface.HardwareAddr)
	buf.WriteN(64)
	buf.WriteN(128)
	buf.WriteBytes(magicCookie[:])
	buf.Write8(uint8(OptionDHCPMessageType))
	buf.Write8(uint8(1))
	buf.Write8(MessageTypeDiscover)
	buf.Write8(uint8(OptionParameterRequestList))
	buf.Write8(uint8(2))
	buf.Write8(uint8(OptionDomainName))
	buf.Write8(uint8(OptionDHCPMessageType))
	buf.Write8(uint8(OptionEnd))

	return nil
}

func htons(v uint16) uint16 {
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], v)
	return binary.LittleEndian.Uint16(tmp[:])
}
