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

package winrm

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseWinRMIdentifyResponse_Valid tests parsing of valid SOAP IdentifyResponse messages
func TestParseWinRMIdentifyResponse_Valid(t *testing.T) {
	tests := []struct {
		name                string
		response            string
		expectDetected      bool
		expectedProtocolVer string
		expectedVendor      string
		expectedProduct     string
		expectedOSVersion   string
	}{
		{
			name: "Windows Server 2019 (OS: 10.0.17763 SP: 0.0 Stack: 3.0)",
			response: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">` +
				`<s:Body>` +
				`<wsmid:IdentifyResponse>` +
				`<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>` +
				`<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>` +
				`<wsmid:ProductVersion>OS: 10.0.17763 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>` +
				`</wsmid:IdentifyResponse>` +
				`</s:Body>` +
				`</s:Envelope>`,
			expectDetected:      true,
			expectedProtocolVer: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
			expectedVendor:      "Microsoft Corporation",
			expectedProduct:     "OS: 10.0.17763 SP: 0.0 Stack: 3.0",
			expectedOSVersion:   "10.0.17763",
		},
		{
			name: "Windows Server 2022 (OS: 10.0.20348 SP: 0.0 Stack: 3.0)",
			response: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">` +
				`<s:Body>` +
				`<wsmid:IdentifyResponse>` +
				`<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>` +
				`<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>` +
				`<wsmid:ProductVersion>OS: 10.0.20348 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>` +
				`</wsmid:IdentifyResponse>` +
				`</s:Body>` +
				`</s:Envelope>`,
			expectDetected:      true,
			expectedProtocolVer: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
			expectedVendor:      "Microsoft Corporation",
			expectedProduct:     "OS: 10.0.20348 SP: 0.0 Stack: 3.0",
			expectedOSVersion:   "10.0.20348",
		},
		{
			name: "Windows Server 2016 (OS: 10.0.14393 SP: 0.0 Stack: 3.0)",
			response: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">` +
				`<s:Body>` +
				`<wsmid:IdentifyResponse>` +
				`<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>` +
				`<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>` +
				`<wsmid:ProductVersion>OS: 10.0.14393 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>` +
				`</wsmid:IdentifyResponse>` +
				`</s:Body>` +
				`</s:Envelope>`,
			expectDetected:      true,
			expectedProtocolVer: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
			expectedVendor:      "Microsoft Corporation",
			expectedProduct:     "OS: 10.0.14393 SP: 0.0 Stack: 3.0",
			expectedOSVersion:   "10.0.14393",
		},
		{
			name: "Minimal response (just ProtocolVersion and ProductVendor, no ProductVersion)",
			response: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">` +
				`<s:Body>` +
				`<wsmid:IdentifyResponse>` +
				`<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>` +
				`<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>` +
				`</wsmid:IdentifyResponse>` +
				`</s:Body>` +
				`</s:Envelope>`,
			expectDetected:      true,
			expectedProtocolVer: "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
			expectedVendor:      "Microsoft Corporation",
			expectedProduct:     "",
			expectedOSVersion:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseWinRMIdentifyResponse([]byte(tt.response))
			if tt.expectDetected {
				require.NotNil(t, result, "Expected detection result")
				assert.True(t, result.detected, "Detection result should be true")
				assert.Equal(t, tt.expectedProtocolVer, result.protocolVersion, "ProtocolVersion mismatch")
				assert.Equal(t, tt.expectedVendor, result.productVendor, "ProductVendor mismatch")
				assert.Equal(t, tt.expectedProduct, result.productVersion, "ProductVersion mismatch")
				assert.Equal(t, tt.expectedOSVersion, result.osVersion, "OSVersion mismatch")
			} else {
				assert.Nil(t, result, "Expected nil result for invalid response")
			}
		})
	}
}

// TestParseWinRMIdentifyResponse_Invalid tests rejection of invalid responses
func TestParseWinRMIdentifyResponse_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{
			name:     "Empty response",
			response: "",
		},
		{
			name:     "Non-XML body (plain text)",
			response: "OK",
		},
		{
			name: "Valid XML but no IdentifyResponse element",
			response: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">` +
				`<s:Body>` +
				`<SomeOtherResponse>` +
				`<Status>success</Status>` +
				`</SomeOtherResponse>` +
				`</s:Body>` +
				`</s:Envelope>`,
		},
		{
			name: "XML with empty ProtocolVersion",
			response: `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">` +
				`<s:Body>` +
				`<wsmid:IdentifyResponse>` +
				`<wsmid:ProtocolVersion></wsmid:ProtocolVersion>` +
				`<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>` +
				`</wsmid:IdentifyResponse>` +
				`</s:Body>` +
				`</s:Envelope>`,
		},
		{
			name: "HTML response (common when hitting wrong service)",
			response: `<!DOCTYPE html>` +
				`<html>` +
				`<head><title>404 Not Found</title></head>` +
				`<body><h1>Not Found</h1></body>` +
				`</html>`,
		},
		{
			name:     "Oversized response (>10KB, should be rejected)",
			response: strings.Repeat("A", 11*1024), // 11KB of data
		},
		{
			name:     "JSON response (not XML)",
			response: `{"status":"success","version":"1.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseWinRMIdentifyResponse([]byte(tt.response))
			assert.Nil(t, result, "Expected nil result for invalid response")
		})
	}
}

// TestExtractOSVersion tests OS version extraction from ProductVersion string
func TestExtractOSVersion(t *testing.T) {
	tests := []struct {
		name              string
		productVersion    string
		expectedOSVersion string
	}{
		{
			name:              "Valid: OS: 10.0.17763 SP: 0.0 Stack: 3.0",
			productVersion:    "OS: 10.0.17763 SP: 0.0 Stack: 3.0",
			expectedOSVersion: "10.0.17763",
		},
		{
			name:              "Valid: OS: 10.0.20348 SP: 0.0 Stack: 3.0",
			productVersion:    "OS: 10.0.20348 SP: 0.0 Stack: 3.0",
			expectedOSVersion: "10.0.20348",
		},
		{
			name:              "Valid: OS: 6.3.9600 SP: 0.0 Stack: 3.0 (Server 2012 R2)",
			productVersion:    "OS: 6.3.9600 SP: 0.0 Stack: 3.0",
			expectedOSVersion: "6.3.9600",
		},
		{
			name:              "Invalid: Some random string",
			productVersion:    "Some random string",
			expectedOSVersion: "",
		},
		{
			name:              "Invalid: empty string",
			productVersion:    "",
			expectedOSVersion: "",
		},
		{
			name:              "Invalid: OS: not.a.version",
			productVersion:    "OS: not.a.version",
			expectedOSVersion: "",
		},
		{
			name:              "Invalid: OS: 999.999.999999 (too many digits in build)",
			productVersion:    "OS: 999.999.999999",
			expectedOSVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osVersion := extractOSVersion(tt.productVersion)
			assert.Equal(t, tt.expectedOSVersion, osVersion, "OS version mismatch")
		})
	}
}

// TestParseHTTPStatusCode tests HTTP status code parsing from response first line
func TestParseHTTPStatusCode(t *testing.T) {
	tests := []struct {
		name               string
		response           string
		expectedStatusCode int
	}{
		{
			name:               "HTTP/1.1 200 OK\\r\\n...",
			response:           "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n",
			expectedStatusCode: 200,
		},
		{
			name:               "HTTP/1.1 401 Unauthorized\\r\\n...",
			response:           "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\n",
			expectedStatusCode: 401,
		},
		{
			name:               "HTTP/1.1 404 Not Found\\r\\n...",
			response:           "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n",
			expectedStatusCode: 404,
		},
		{
			name:               "HTTP/1.0 200 OK\\r\\n... (HTTP 1.0)",
			response:           "HTTP/1.0 200 OK\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n",
			expectedStatusCode: 200,
		},
		{
			name:               "HTTP/1.1 200 OK\\n... (\\n only line ending)",
			response:           "HTTP/1.1 200 OK\nContent-Type: text/xml\n\n",
			expectedStatusCode: 200,
		},
		{
			name:               "Empty response",
			response:           "",
			expectedStatusCode: 0,
		},
		{
			name:               "Garbage response",
			response:           "garbage",
			expectedStatusCode: 0,
		},
		{
			name:               "HTTP/1.1 999 Invalid\\r\\n (invalid range >= 600)",
			response:           "HTTP/1.1 999 Invalid\r\n\r\n",
			expectedStatusCode: 0,
		},
		{
			name:               "Short response 'HTTP'",
			response:           "HTTP",
			expectedStatusCode: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statusCode := parseHTTPStatusCode([]byte(tt.response))
			assert.Equal(t, tt.expectedStatusCode, statusCode, "Status code mismatch")
		})
	}
}

// TestCheckMicrosoftHTTPAPI tests detection of Microsoft-HTTPAPI header
func TestCheckMicrosoftHTTPAPI(t *testing.T) {
	tests := []struct {
		name     string
		response string
		expected bool
	}{
		{
			name: "Response containing Server: Microsoft-HTTPAPI/2.0",
			response: "HTTP/1.1 401 Unauthorized\r\n" +
				"Server: Microsoft-HTTPAPI/2.0\r\n" +
				"WWW-Authenticate: Basic\r\n" +
				"\r\n",
			expected: true,
		},
		{
			name: "Response without Microsoft-HTTPAPI",
			response: "HTTP/1.1 200 OK\r\n" +
				"Server: nginx/1.18.0\r\n" +
				"\r\n",
			expected: false,
		},
		{
			name:     "Empty response",
			response: "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkMicrosoftHTTPAPI([]byte(tt.response))
			assert.Equal(t, tt.expected, result, "Microsoft-HTTPAPI detection mismatch")
		})
	}
}

// TestBuildWinRMCPE tests CPE generation for WinRM
func TestBuildWinRMCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectedCPE string
	}{
		{
			name:        "With version 10.0.17763",
			version:     "10.0.17763",
			expectedCPE: "cpe:2.3:a:microsoft:windows_remote_management:10.0.17763:*:*:*:*:*:*:*",
		},
		{
			name:        "Empty version",
			version:     "",
			expectedCPE: "cpe:2.3:a:microsoft:windows_remote_management:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildWinRMCPE(tt.version)
			assert.Equal(t, tt.expectedCPE, cpe, "CPE mismatch")
		})
	}
}

// TestBuildWinRMHTTPRequest tests HTTP request building
func TestBuildWinRMHTTPRequest(t *testing.T) {
	host := "testhost:5985"
	request := buildWinRMHTTPRequest(host)

	// Verify the request contains required components
	assert.Contains(t, request, "POST /wsman HTTP/1.1", "Missing POST /wsman HTTP/1.1")
	assert.Contains(t, request, "Content-Type: application/soap+xml;charset=UTF-8", "Missing Content-Type header")
	assert.Contains(t, request, "Content-Length:", "Missing Content-Length header")
	assert.Contains(t, request, "Host: testhost:5985", "Missing Host header")
	assert.Contains(t, request, "<wsmid:Identify/>", "Missing SOAP Identify envelope in body")
}

// TestExtractHTTPBody tests extracting body from HTTP response
func TestExtractHTTPBody(t *testing.T) {
	tests := []struct {
		name         string
		httpResponse string
		expectedBody string
	}{
		{
			name: "Valid HTTP response with \\r\\n\\r\\n separator",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/soap+xml\r\n" +
				"\r\n" +
				`<s:Envelope>...</s:Envelope>`,
			expectedBody: `<s:Envelope>...</s:Envelope>`,
		},
		{
			name:         "No separator",
			httpResponse: "just plain text",
			expectedBody: "just plain text",
		},
		{
			name: "Headers only (no body after separator)",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/plain\r\n" +
				"\r\n",
			expectedBody: "",
		},
		{
			name:         "Empty response (returns empty slice, not nil)",
			httpResponse: "",
			expectedBody: "", // Will be empty slice []byte{}, not nil
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := extractHTTPBody([]byte(tt.httpResponse))
			if tt.expectedBody == "" && len(tt.httpResponse) > 0 && !strings.Contains(tt.httpResponse, "\r\n\r\n") {
				// Special case: no separator means return original
				assert.Equal(t, tt.httpResponse, string(body), "Body mismatch for no-separator case")
			} else if tt.expectedBody == "" && tt.httpResponse == "" {
				// Empty input returns empty slice, not nil
				assert.Equal(t, []byte{}, body, "Expected empty slice for empty input")
			} else if tt.expectedBody == "" {
				assert.Nil(t, body, "Expected nil body when headers present but no body")
			} else {
				assert.Equal(t, tt.expectedBody, string(body), "Body mismatch")
			}
		})
	}
}

// TestWinRMPlugin_Name tests the Name method for WinRMPlugin
func TestWinRMPlugin_Name(t *testing.T) {
	plugin := &WinRMPlugin{}
	assert.Equal(t, "winrm", plugin.Name())
}

// TestWinRMPlugin_Type tests the Type method for WinRMPlugin
func TestWinRMPlugin_Type(t *testing.T) {
	plugin := &WinRMPlugin{}
	assert.Equal(t, plugins.TCP, plugin.Type())
}

// TestWinRMPlugin_PortPriority tests port prioritization for WinRMPlugin
func TestWinRMPlugin_PortPriority(t *testing.T) {
	plugin := &WinRMPlugin{}

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{
			name:     "Port 5985 (WinRM HTTP)",
			port:     5985,
			expected: true,
		},
		{
			name:     "Port 80 (HTTP)",
			port:     80,
			expected: false,
		},
		{
			name:     "Port 5986 (WinRM HTTPS)",
			port:     5986,
			expected: false,
		},
		{
			name:     "Port 443 (HTTPS)",
			port:     443,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.PortPriority(tt.port)
			assert.Equal(t, tt.expected, result, "PortPriority mismatch")
		})
	}
}

// TestWinRMPlugin_Priority tests priority for WinRMPlugin
func TestWinRMPlugin_Priority(t *testing.T) {
	plugin := &WinRMPlugin{}
	assert.Equal(t, 100, plugin.Priority())
}

// TestWinRMTLSPlugin_Name tests the Name method for WinRMTLSPlugin
func TestWinRMTLSPlugin_Name(t *testing.T) {
	plugin := &WinRMTLSPlugin{}
	assert.Equal(t, "winrm", plugin.Name())
}

// TestWinRMTLSPlugin_Type tests the Type method for WinRMTLSPlugin
func TestWinRMTLSPlugin_Type(t *testing.T) {
	plugin := &WinRMTLSPlugin{}
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
}

// TestWinRMTLSPlugin_PortPriority tests port prioritization for WinRMTLSPlugin
func TestWinRMTLSPlugin_PortPriority(t *testing.T) {
	plugin := &WinRMTLSPlugin{}

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{
			name:     "Port 5986 (WinRM HTTPS)",
			port:     5986,
			expected: true,
		},
		{
			name:     "Port 443 (HTTPS)",
			port:     443,
			expected: false,
		},
		{
			name:     "Port 5985 (WinRM HTTP)",
			port:     5985,
			expected: false,
		},
		{
			name:     "Port 80 (HTTP)",
			port:     80,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.PortPriority(tt.port)
			assert.Equal(t, tt.expected, result, "PortPriority mismatch")
		})
	}
}

// TestWinRMTLSPlugin_Priority tests priority for WinRMTLSPlugin
func TestWinRMTLSPlugin_Priority(t *testing.T) {
	plugin := &WinRMTLSPlugin{}
	assert.Equal(t, 101, plugin.Priority())
}

// TestPluginsDifferentPorts verifies plain and TLS plugins use different ports
func TestPluginsDifferentPorts(t *testing.T) {
	plainPlugin := &WinRMPlugin{}
	tlsPlugin := &WinRMTLSPlugin{}

	// Verify plain plugin prioritizes 5985, not 5986
	assert.True(t, plainPlugin.PortPriority(5985), "Plain plugin should prioritize port 5985")
	assert.False(t, plainPlugin.PortPriority(5986), "Plain plugin should NOT prioritize port 5986")

	// Verify TLS plugin prioritizes 5986, not 5985
	assert.True(t, tlsPlugin.PortPriority(5986), "TLS plugin should prioritize port 5986")
	assert.False(t, tlsPlugin.PortPriority(5985), "TLS plugin should NOT prioritize port 5985")

	// Verify different transport types
	assert.Equal(t, plugins.TCP, plainPlugin.Type(), "Plain plugin should use TCP transport")
	assert.Equal(t, plugins.TCPTLS, tlsPlugin.Type(), "TLS plugin should use TCPTLS transport")

	// Verify different priorities
	assert.Equal(t, 100, plainPlugin.Priority(), "Plain plugin should have priority 100")
	assert.Equal(t, 101, tlsPlugin.Priority(), "TLS plugin should have priority 101")
}

// TestDetectWinRM_IdentifyResponse tests detectWinRM with valid IdentifyResponse
func TestDetectWinRM_IdentifyResponse(t *testing.T) {
	// Create mock connection using net.Pipe()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Create target
	target := plugins.Target{
		Address: mustParseAddrPort("127.0.0.1:5985"),
		Host:    "127.0.0.1",
	}

	// Mock HTTP response with valid SOAP IdentifyResponse
	mockResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/soap+xml;charset=UTF-8\r\n" +
		"Server: Microsoft-HTTPAPI/2.0\r\n" +
		"\r\n" +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">` +
		`<s:Body>` +
		`<wsmid:IdentifyResponse>` +
		`<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>` +
		`<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>` +
		`<wsmid:ProductVersion>OS: 10.0.17763 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>` +
		`</wsmid:IdentifyResponse>` +
		`</s:Body>` +
		`</s:Envelope>`

	// Start goroutine to handle server side
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Read the request (discard it)
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)

		// Write mock response
		_, _ = server.Write([]byte(mockResponse))
		server.Close()
	}()

	// Call detectWinRM
	service, err := detectWinRM(client, target, time.Second*2, false)

	// Wait for goroutine to complete
	<-done

	// Verify results
	require.NoError(t, err)
	require.NotNil(t, service, "Service should be detected")
	assert.Equal(t, "10.0.17763", service.Version, "Version should match OS version")
	assert.Equal(t, "winrm", service.Protocol, "Protocol should be winrm")
}

// TestDetectWinRM_401Unauthorized tests detectWinRM with 401 response (auth required)
func TestDetectWinRM_401Unauthorized(t *testing.T) {
	// Create mock connection using net.Pipe()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Create target
	target := plugins.Target{
		Address: mustParseAddrPort("127.0.0.1:5985"),
		Host:    "127.0.0.1",
	}

	// Mock HTTP 401 response with Microsoft-HTTPAPI header
	mockResponse := "HTTP/1.1 401 Unauthorized\r\n" +
		"Server: Microsoft-HTTPAPI/2.0\r\n" +
		"WWW-Authenticate: Negotiate\r\n" +
		"\r\n"

	// Start goroutine to handle server side
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Read the request (discard it)
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)

		// Write mock response
		_, _ = server.Write([]byte(mockResponse))
		server.Close()
	}()

	// Call detectWinRM
	service, err := detectWinRM(client, target, time.Second*2, false)

	// Wait for goroutine to complete
	<-done

	// Verify results
	require.NoError(t, err)
	require.NotNil(t, service, "Service should be detected via fallback")
	assert.Equal(t, "", service.Version, "Version should be empty (no version available)")
}

// TestDetectWinRM_NotWinRM tests detectWinRM with non-WinRM response
func TestDetectWinRM_NotWinRM(t *testing.T) {
	// Create mock connection using net.Pipe()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Create target
	target := plugins.Target{
		Address: mustParseAddrPort("127.0.0.1:5985"),
		Host:    "127.0.0.1",
	}

	// Mock non-WinRM response
	mockResponse := "HTTP/1.1 200 OK\r\n" +
		"Server: Apache/2.4\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html>Not WinRM</html>"

	// Start goroutine to handle server side
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Read the request (discard it)
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)

		// Write mock response
		_, _ = server.Write([]byte(mockResponse))
		server.Close()
	}()

	// Call detectWinRM
	service, err := detectWinRM(client, target, time.Second*2, false)

	// Wait for goroutine to complete
	<-done

	// Verify results
	require.NoError(t, err)
	assert.Nil(t, service, "Service should not be detected")
}

// TestDetectWinRM_EmptyResponse tests detectWinRM with empty response (connection closes immediately)
func TestDetectWinRM_EmptyResponse(t *testing.T) {
	// Create mock connection using net.Pipe()
	client, server := net.Pipe()
	defer client.Close()

	// Create target
	target := plugins.Target{
		Address: mustParseAddrPort("127.0.0.1:5985"),
		Host:    "127.0.0.1",
	}

	// Start goroutine to handle server side - close immediately
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Read the request (discard it)
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)

		// Close immediately without writing anything
		server.Close()
	}()

	// Call detectWinRM
	service, _ := detectWinRM(client, target, time.Second*2, false)

	// Wait for goroutine to complete
	<-done

	// Verify results - should not panic, should return nil service
	// Error is expected when connection closes (EOF), so we ignore it
	assert.Nil(t, service)
}

// TestWinRMPlugin_Run tests the Run method for WinRMPlugin (TCP)
func TestWinRMPlugin_Run(t *testing.T) {
	plugin := &WinRMPlugin{}

	// Create mock connection using net.Pipe()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Create target
	target := plugins.Target{
		Address: mustParseAddrPort("127.0.0.1:5985"),
		Host:    "127.0.0.1",
	}

	// Mock HTTP response with valid SOAP IdentifyResponse
	mockResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/soap+xml;charset=UTF-8\r\n" +
		"Server: Microsoft-HTTPAPI/2.0\r\n" +
		"\r\n" +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">` +
		`<s:Body>` +
		`<wsmid:IdentifyResponse>` +
		`<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>` +
		`<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>` +
		`<wsmid:ProductVersion>OS: 10.0.17763 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>` +
		`</wsmid:IdentifyResponse>` +
		`</s:Body>` +
		`</s:Envelope>`

	// Start goroutine to handle server side
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Read the request (discard it)
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)

		// Write mock response
		_, _ = server.Write([]byte(mockResponse))
		server.Close()
	}()

	// Call Run method
	service, err := plugin.Run(client, time.Second*2, target)

	// Wait for goroutine to complete
	<-done

	// Verify results
	require.NoError(t, err)
	require.NotNil(t, service, "Service should be detected")
	assert.Equal(t, "10.0.17763", service.Version, "Version should match OS version")
	assert.Equal(t, "winrm", service.Protocol, "Protocol should be winrm for WinRMPlugin")
}

// TestWinRMTLSPlugin_Run tests the Run method for WinRMTLSPlugin (TCPTLS)
func TestWinRMTLSPlugin_Run(t *testing.T) {
	plugin := &WinRMTLSPlugin{}

	// Create mock connection using net.Pipe()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Create target
	target := plugins.Target{
		Address: mustParseAddrPort("127.0.0.1:5986"),
		Host:    "127.0.0.1",
	}

	// Mock HTTP response with valid SOAP IdentifyResponse
	mockResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/soap+xml;charset=UTF-8\r\n" +
		"Server: Microsoft-HTTPAPI/2.0\r\n" +
		"\r\n" +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd">` +
		`<s:Body>` +
		`<wsmid:IdentifyResponse>` +
		`<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>` +
		`<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>` +
		`<wsmid:ProductVersion>OS: 10.0.20348 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>` +
		`</wsmid:IdentifyResponse>` +
		`</s:Body>` +
		`</s:Envelope>`

	// Start goroutine to handle server side
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Read the request (discard it)
		buf := make([]byte, 4096)
		_, _ = server.Read(buf)

		// Write mock response
		_, _ = server.Write([]byte(mockResponse))
		server.Close()
	}()

	// Call Run method
	service, err := plugin.Run(client, time.Second*2, target)

	// Wait for goroutine to complete
	<-done

	// Verify results
	require.NoError(t, err)
	require.NotNil(t, service, "Service should be detected")
	assert.Equal(t, "10.0.20348", service.Version, "Version should match OS version")
	assert.Equal(t, "winrm", service.Protocol, "Protocol should be winrm for WinRMTLSPlugin")
}

// Helper function to parse address
func mustParseAddrPort(s string) netip.AddrPort {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		panic(err)
	}
	return addr
}
