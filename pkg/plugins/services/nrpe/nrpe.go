// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package nrpe implements service detection for Nagios Remote Plugin Executor (NRPE) using the v2 binary protocol.

Detection Strategy:
1. Sends NRPE v2 query packet (1034 bytes):
   - 2-byte packet_version (big-endian, value = 2)
   - 2-byte packet_type (big-endian, value = 1 for Query)
   - 4-byte crc32_value (big-endian, CRC-32/IEEE over entire packet with crc32 field set to 0)
   - 2-byte result_code (big-endian, value = 0)
   - 1024-byte buffer (null-terminated command string "_NRPE_CHECK", zero-padded)
2. Validates server NRPE v2 response packet:
   - Minimum 1034 bytes required (fixed v2 packet size)
   - Bytes 0-1: packet_version must be 2
   - Bytes 2-3: packet_type must be 2 (Response)
   - Bytes 4-7: crc32_value must be valid
   - Bytes 10-1033: buffer contains "NRPE v" prefix indicating version
3. Extracts version from response buffer using regex `NRPE v(\d+\.\d+(?:\.\d+)?)`
4. Returns Service with version-specific CPE or wildcard CPE if version unknown
*/
package nrpe

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"regexp"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	NRPE             = "nrpe"
	PacketVersion2   = 2
	QueryPacket      = 1
	ResponsePacket   = 2
	PacketSize       = 1034 // Fixed v2 packet size
	BufferSize       = 1024
	NRPECheckCommand = "_NRPE_CHECK"
)

type NRPEPlugin struct{}
type NRPETLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&NRPEPlugin{})
	plugins.RegisterPlugin(&NRPETLSPlugin{})
}

// buildNRPEQuery constructs the NRPE v2 query packet with CRC32
func buildNRPEQuery() []byte {
	// 1034-byte packet: version(2) + type(2) + crc32(4) + result(2) + buffer(1024)
	packet := make([]byte, PacketSize)

	// Packet version: 2 (big-endian uint16)
	binary.BigEndian.PutUint16(packet[0:2], PacketVersion2)

	// Packet type: 1 = Query (big-endian uint16)
	binary.BigEndian.PutUint16(packet[2:4], QueryPacket)

	// CRC32: initially 0, will be calculated below (big-endian uint32)
	binary.BigEndian.PutUint32(packet[4:8], 0)

	// Result code: 0 (big-endian uint16)
	binary.BigEndian.PutUint16(packet[8:10], 0)

	// Buffer: "_NRPE_CHECK" null-terminated, zero-padded to 1024 bytes
	copy(packet[10:], NRPECheckCommand)
	// Rest of buffer (from 10+len(command) to 1034) is already zero-initialized

	// Calculate CRC32 (CRC-32/IEEE polynomial 0xEDB88320) over entire packet
	crc := crc32.ChecksumIEEE(packet)
	binary.BigEndian.PutUint32(packet[4:8], crc)

	return packet
}

// isValidNRPEResponse validates an NRPE v2 response packet structure
func isValidNRPEResponse(response []byte) bool {
	// NRPE v2 response must be exactly 1034 bytes
	if len(response) < PacketSize {
		return false
	}

	// Check packet_version (bytes 0-1, big-endian, must be 2)
	version := binary.BigEndian.Uint16(response[0:2])
	if version != PacketVersion2 {
		return false
	}

	// Check packet_type (bytes 2-3, big-endian, must be 2 for Response)
	packetType := binary.BigEndian.Uint16(response[2:4])
	if packetType != ResponsePacket {
		return false
	}

	return true
}

// parseNRPEVersion extracts the NRPE version from response buffer
func parseNRPEVersion(response []byte) string {
	if len(response) < PacketSize {
		return ""
	}

	// Buffer starts at byte 10, is 1024 bytes long
	buffer := string(response[10:PacketSize])

	// Extract version using regex: "NRPE v1.2.3" or "NRPE v4.1" etc.
	re := regexp.MustCompile(`NRPE v(\d+\.\d+(?:\.\d+)?)`)
	matches := re.FindStringSubmatch(buffer)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// generateCPE creates CPE identifier for NRPE services
func generateCPE(version string) []string {
	if version != "" {
		return []string{fmt.Sprintf("cpe:2.3:a:nagios:nrpe:%s:*:*:*:*:*:*:*", version)}
	}
	// Wildcard CPE when version is unknown
	return []string{"cpe:2.3:a:nagios:nrpe:*:*:*:*:*:*:*:*"}
}

// detectNRPE performs NRPE protocol detection
func detectNRPE(conn net.Conn, timeout time.Duration) (version string, detected bool, err error) {
	// Send NRPE v2 query packet
	probe := buildNRPEQuery()
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return "", false, err
	}

	if len(response) == 0 {
		return "", false, &utils.ServerNotEnable{}
	}

	// Validate NRPE v2 response
	if !isValidNRPEResponse(response) {
		return "", false, &utils.InvalidResponseError{Service: NRPE}
	}

	// Extract version from buffer
	version = parseNRPEVersion(response)

	return version, true, nil
}

// NRPEPlugin implements TCP NRPE detection
func (p *NRPEPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := detectNRPE(conn, timeout)
	if err != nil {
		if _, ok := err.(*utils.ServerNotEnable); ok {
			return nil, nil
		}
		if _, ok := err.(*utils.InvalidResponseError); ok {
			return nil, nil
		}
		return nil, err
	}

	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceNRPE{
		CPEs: generateCPE(version),
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *NRPEPlugin) PortPriority(port uint16) bool {
	return port == 5666
}

func (p *NRPEPlugin) Name() string {
	return NRPE
}

func (p *NRPEPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *NRPEPlugin) Priority() int {
	return 410
}

// NRPETLSPlugin implements TCPTLS NRPE detection
func (p *NRPETLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := detectNRPE(conn, timeout)
	if err != nil {
		if _, ok := err.(*utils.ServerNotEnable); ok {
			return nil, nil
		}
		if _, ok := err.(*utils.InvalidResponseError); ok {
			return nil, nil
		}
		return nil, err
	}

	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceNRPE{
		CPEs: generateCPE(version),
	}

	return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
}

func (p *NRPETLSPlugin) PortPriority(port uint16) bool {
	return port == 5666
}

func (p *NRPETLSPlugin) Name() string {
	return NRPE
}

func (p *NRPETLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *NRPETLSPlugin) Priority() int {
	return 410
}
