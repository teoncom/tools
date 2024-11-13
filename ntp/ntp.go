package ntp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const (
	// NTP packet size - 48 bytes of fixed-format data
	ntpPacketSize = 48

	// NTP protocol version (4)
	ntpVersion = 4

	// Mode client - 3
	ntpModeClient = 3

	// Seconds between Unix epoch (1970) and NTP epoch (1900)
	ntpEpochOffset = 2208988800
)

// NTPPacket represents an NTP packet
type NTPPacket struct {
	Settings       uint8  // Leap Indicator (2 bits), Version (3 bits), Mode (3 bits)
	Stratum        uint8  // Stratum level of the local clock
	Poll           int8   // Maximum interval between successive messages
	Precision      int8   // Precision of the local clock
	RootDelay      uint32 // Total round-trip delay to the reference clock
	RootDispersion uint32 // Total dispersion to the reference clock
	ReferenceID    uint32 // Reference identifier
	RefTimeSec     uint32 // Reference timestamp seconds
	RefTimeFrac    uint32 // Reference timestamp fractional
	OrigTimeSec    uint32 // Origin timestamp seconds
	OrigTimeFrac   uint32 // Origin timestamp fractional
	RxTimeSec      uint32 // Receive timestamp seconds
	RxTimeFrac     uint32 // Receive timestamp fractional
	TxTimeSec      uint32 // Transmit timestamp seconds
	TxTimeFrac     uint32 // Transmit timestamp fractional
}

// Time queries the NTP server and returns the current time
func Time(server string) (time.Time, error) {
	// Create a UDP address for the NTP server
	addr, err := net.ResolveUDPAddr("udp", server+":123")
	if err != nil {
		return time.Time{}, fmt.Errorf("error resolving UDP address: %v", err)
	}

	// Open a UDP connection
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return time.Time{}, fmt.Errorf("error connecting to NTP server: %v", err)
	}
	defer conn.Close()

	// Set a timeout for the entire operation
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return time.Time{}, fmt.Errorf("error setting deadline: %v", err)
	}

	// Initialize the NTP packet
	packet := &NTPPacket{
		Settings: uint8(ntpVersion<<3 | ntpModeClient),
	}

	// Convert NTP packet to bytes
	req := make([]byte, ntpPacketSize)
	req[0] = packet.Settings

	// Send the request
	if _, err := conn.Write(req); err != nil {
		return time.Time{}, fmt.Errorf("error sending NTP packet: %v", err)
	}

	// Read the response
	resp := make([]byte, ntpPacketSize)
	_, err = conn.Read(resp)
	if err != nil {
		return time.Time{}, fmt.Errorf("error reading NTP packet: %v", err)
	}

	// Extract the transmit timestamp (seconds and fractional part)
	txSec := binary.BigEndian.Uint32(resp[40:44])
	txFrac := binary.BigEndian.Uint32(resp[44:48])

	// Convert NTP timestamp to UNIX timestamp
	// Remove NTP epoch offset and add fractional part
	sec := float64(txSec) - ntpEpochOffset
	frac := float64(txFrac) / (1 << 32)

	return time.Unix(int64(sec), int64(frac*1e9)), nil
}
