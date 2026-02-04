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

package amqp

import (
	"bytes"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestProtocolHeader verifies the AMQP 0-9-1 protocol header is correctly constructed
func TestProtocolHeader(t *testing.T) {
	expected := []byte{'A', 'M', 'Q', 'P', 0x00, 0x00, 0x09, 0x01}
	header := buildProtocolHeader()

	if !bytes.Equal(header, expected) {
		t.Errorf("Protocol header mismatch. Expected %v, got %v", expected, header)
	}
}

// TestValidConnectionStart verifies detection of valid AMQP Connection.Start response
func TestValidConnectionStart(t *testing.T) {
	// Valid Connection.Start method frame
	// Frame type: 0x01 (Method)
	// Channel: 0x0000
	// Payload: class(2) + method(2) + version(2) + empty_table(4) + mechanisms(9) + locales(9) = 28 bytes (0x1C)
	response := []byte{
		0x01,       // Frame type (Method)
		0x00, 0x00, // Channel 0
		0x00, 0x00, 0x00, 0x1C, // Payload size (28 bytes)
		// Payload starts here:
		0x00, 0x0A, // Class ID (10 - Connection)
		0x00, 0x0A, // Method ID (10 - Start)
		0x00, 0x09, // Version major(0) minor(9)
		0x00, 0x00, 0x00, 0x00, // Empty server properties table
		0x00, 0x00, 0x00, 0x05, 'P', 'L', 'A', 'I', 'N', // Mechanisms (5-byte string "PLAIN")
		0x00, 0x00, 0x00, 0x05, 'e', 'n', '_', 'U', 'S', // Locales (5-byte string "en_US")
		0xCE, // Frame end
	}

	result := isValidConnectionStart(response)
	if !result {
		t.Errorf("Valid Connection.Start frame was not recognized, response length: %d", len(response))
	}
}

// TestInvalidFrameType verifies rejection of invalid frame types
func TestInvalidFrameType(t *testing.T) {
	response := []byte{
		0x02,       // Invalid frame type (not 0x01)
		0x00, 0x00, // Channel
		0x00, 0x00, 0x00, 0x08, // Payload size
		0x00, 0x0A, // Class ID
		0x00, 0x0A, // Method ID
		0xCE, // Frame end
	}

	result := isValidConnectionStart(response)
	if result {
		t.Error("Invalid frame type was incorrectly accepted")
	}
}

// TestInvalidClassMethod verifies rejection of wrong class/method IDs
func TestInvalidClassMethod(t *testing.T) {
	response := []byte{
		0x01,       // Frame type
		0x00, 0x00, // Channel
		0x00, 0x00, 0x00, 0x08, // Payload size
		0x00, 0x14, // Wrong class ID
		0x00, 0x0A, // Method ID
		0xCE, // Frame end
	}

	result := isValidConnectionStart(response)
	if result {
		t.Error("Wrong class ID was incorrectly accepted")
	}
}

// TestServerPropertyParsing verifies extraction of server properties
func TestServerPropertyParsing(t *testing.T) {
	// Server properties field table
	// Product: RabbitMQ, Version: 3.12.0, Platform: Erlang/OTP 26
	// Calculate exact table length:
	// product: 1(namelen) + 7(name) + 1(type) + 4(valuelen) + 8(value) = 21
	// version: 1 + 7 + 1 + 4 + 6 = 19
	// platform: 1 + 8 + 1 + 4 + 13 = 27
	// Total: 21 + 19 + 27 = 67 bytes
	properties := []byte{
		// Table length (67 = 0x43)
		0x00, 0x00, 0x00, 0x43,
		// Product field
		0x07, 'p', 'r', 'o', 'd', 'u', 'c', 't',
		'S', // Type: long string
		0x00, 0x00, 0x00, 0x08,
		'R', 'a', 'b', 'b', 'i', 't', 'M', 'Q',
		// Version field
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		'S', // Type: long string
		0x00, 0x00, 0x00, 0x06,
		'3', '.', '1', '2', '.', '0',
		// Platform field
		0x08, 'p', 'l', 'a', 't', 'f', 'o', 'r', 'm',
		'S', // Type: long string
		0x00, 0x00, 0x00, 0x0D, // 13 bytes for "Erlang/OTP 26"
		'E', 'r', 'l', 'a', 'n', 'g', '/', 'O', 'T', 'P', ' ', '2', '6',
	}

	product, version, platform := parseServerProperties(properties)

	if product != "RabbitMQ" {
		t.Errorf("Expected product 'RabbitMQ', got '%s'", product)
	}
	if version != "3.12.0" {
		t.Errorf("Expected version '3.12.0', got '%s'", version)
	}
	if platform != "Erlang/OTP 26" {
		t.Errorf("Expected platform 'Erlang/OTP 26', got '%s'", platform)
	}
}

// TestTCPPluginType verifies TCP plugin returns correct protocol type
func TestTCPPluginType(t *testing.T) {
	plugin := &AMQPPlugin{}
	if plugin.Type() != plugins.TCP {
		t.Errorf("Expected TCP protocol, got %v", plugin.Type())
	}
}

// TestTLSPluginType verifies TLS plugin returns correct protocol type
func TestTLSPluginType(t *testing.T) {
	plugin := &TLSPlugin{}
	if plugin.Type() != plugins.TCPTLS {
		t.Errorf("Expected TCPTLS protocol, got %v", plugin.Type())
	}
}

// TestTCPPortPriority verifies TCP plugin prioritizes port 5672
func TestTCPPortPriority(t *testing.T) {
	plugin := &AMQPPlugin{}
	if !plugin.PortPriority(5672) {
		t.Error("Expected port 5672 to have priority")
	}
	if plugin.PortPriority(5671) {
		t.Error("Port 5671 should not have priority for TCP plugin")
	}
}

// TestTLSPortPriority verifies TLS plugin prioritizes port 5671
func TestTLSPortPriority(t *testing.T) {
	plugin := &TLSPlugin{}
	if !plugin.PortPriority(5671) {
		t.Error("Expected port 5671 to have priority")
	}
	if plugin.PortPriority(5672) {
		t.Error("Port 5672 should not have priority for TLS plugin")
	}
}

// TestPluginPriority verifies both plugins have priority 100
func TestPluginPriority(t *testing.T) {
	tcpPlugin := &AMQPPlugin{}
	tlsPlugin := &TLSPlugin{}

	if tcpPlugin.Priority() != 100 {
		t.Errorf("Expected priority 100, got %d", tcpPlugin.Priority())
	}
	if tlsPlugin.Priority() != 100 {
		t.Errorf("Expected priority 100, got %d", tlsPlugin.Priority())
	}
}

// TestEmptyResponse verifies handling of empty server response
func TestEmptyResponse(t *testing.T) {
	response := []byte{}
	result := isValidConnectionStart(response)
	if result {
		t.Error("Empty response should not be valid")
	}
}

// TestTooShortResponse verifies handling of truncated response
func TestTooShortResponse(t *testing.T) {
	response := []byte{0x01, 0x00} // Too short to be valid
	result := isValidConnectionStart(response)
	if result {
		t.Error("Truncated response should not be valid")
	}
}
