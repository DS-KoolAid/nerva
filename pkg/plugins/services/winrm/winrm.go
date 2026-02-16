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
WinRM (Windows Remote Management) Fingerprinting

Detection Strategy:
  PHASE 1 - PRIMARY DETECTION (POST /wsman):
    - Send WS-Management SOAP Identify request
    - Parse XML IdentifyResponse for ProductVendor/ProductVersion

  PHASE 2 - FALLBACK (401 Unauthorized):
    - Check for Microsoft-HTTPAPI/2.0 header
    - Detect WinRM present but auth required

Port Configuration:
  - Port 5985: HTTP (unencrypted WinRM)
  - Port 5986: HTTPS (encrypted WinRM)
*/

package winrm

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	WINRM = "winrm"
)

type WinRMPlugin struct{}
type WinRMTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&WinRMPlugin{})
	plugins.RegisterPlugin(&WinRMTLSPlugin{})
}

// SOAP Envelope structures for parsing WS-Management IdentifyResponse
type soapEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    soapBody `xml:"Body"`
}

type soapBody struct {
	IdentifyResponse identifyResponse `xml:"IdentifyResponse"`
}

type identifyResponse struct {
	ProtocolVersion string `xml:"ProtocolVersion"`
	ProductVendor   string `xml:"ProductVendor"`
	ProductVersion  string `xml:"ProductVersion"`
}

// winrmDetectionResult holds the detection results
type winrmDetectionResult struct {
	detected        bool
	protocolVersion string
	productVendor   string
	productVersion  string
	osVersion       string
	authRequired    bool
}

// parseWinRMIdentifyResponse validates a WinRM IdentifyResponse and extracts info.
//
// Validation rules:
//   - XML must contain <wsmid:IdentifyResponse> element
//   - Extract ProtocolVersion, ProductVendor, ProductVersion if present
//   - Extract OS version from ProductVersion field
//
// Parameters:
//   - response: Raw HTTP response body (expected to be XML)
//
// Returns:
//   - *winrmDetectionResult: Detection result with version info, or nil if not WinRM
func parseWinRMIdentifyResponse(response []byte) *winrmDetectionResult {
	if len(response) == 0 {
		return nil
	}

	// Enforce size limit before parsing to prevent XML bombs
	const maxXMLSize = 10 * 1024 // 10KB reasonable for IdentifyResponse
	if len(response) > maxXMLSize {
		return nil
	}

	// Pre-filter: check for IdentifyResponse in body before full XML parse.
	// All valid WinRM responses contain this string; false positives caught by XML validation below.
	if !strings.Contains(string(response), "IdentifyResponse") {
		return nil
	}

	// Use xml.Decoder for safer parsing
	decoder := xml.NewDecoder(bytes.NewReader(response))
	decoder.Strict = false

	var envelope soapEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil
	}

	// Validate WinRM marker: ProtocolVersion is REQUIRED in all WS-Management
	// IdentifyResponse messages per DMTF DSP0226 §7.1.
	if envelope.Body.IdentifyResponse.ProtocolVersion == "" {
		return nil
	}

	osVersion := extractOSVersion(envelope.Body.IdentifyResponse.ProductVersion)

	return &winrmDetectionResult{
		detected:        true,
		protocolVersion: envelope.Body.IdentifyResponse.ProtocolVersion,
		productVendor:   envelope.Body.IdentifyResponse.ProductVendor,
		productVersion:  envelope.Body.IdentifyResponse.ProductVersion,
		osVersion:       osVersion,
		authRequired:    false,
	}
}

// extractOSVersion extracts the OS version from ProductVersion string.
//
// Example input: "OS: 10.0.17763 SP: 0.0 Stack: 3.0"
// Returns: "10.0.17763"
//
// Windows versions follow MAJOR.MINOR.BUILD format (e.g., "10.0.17763")
// Valid ranges: major (5-11), minor (0-3), build (0-99999)
//
// Parameters:
//   - productVersion: ProductVersion string from IdentifyResponse
//
// Returns:
//   - string: OS version, or empty string if not found
func extractOSVersion(productVersion string) string {
	// Windows versions follow MAJOR.MINOR.BUILD format (e.g., "10.0.17763")
	// Valid ranges: major (5-11), minor (0-3), build (0-99999)
	re := regexp.MustCompile(`OS:\s*(\d{1,2}\.\d{1}\.\d{1,5})`)
	matches := re.FindStringSubmatch(productVersion)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// parseHTTPStatusCode extracts the status code from the HTTP response first line.
//
// Parameters:
//   - response: Full HTTP response
//
// Returns:
//   - int: HTTP status code, or 0 if not found
func parseHTTPStatusCode(response []byte) int {
	if len(response) < 12 { // Minimum: "HTTP/1.0 XXX"
		return 0
	}

	// Find end of first line (handle both \r\n and \n)
	firstLineEnd := bytes.IndexAny(response, "\r\n")
	if firstLineEnd == -1 {
		return 0
	}

	firstLine := string(response[:firstLineEnd])

	// Parse "HTTP/1.1 200 OK" format — split into fields and extract second field
	fields := strings.Fields(firstLine)
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0
	}

	statusCode, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}

	// Validate HTTP status code range
	if statusCode < 100 || statusCode >= 600 {
		return 0
	}

	return statusCode
}

// checkMicrosoftHTTPAPI checks if response contains Microsoft-HTTPAPI header.
//
// Parameters:
//   - response: Full HTTP response
//
// Returns:
//   - bool: true if Microsoft-HTTPAPI header found
func checkMicrosoftHTTPAPI(response []byte) bool {
	return strings.Contains(string(response), "Microsoft-HTTPAPI")
}

// buildWinRMCPE constructs a CPE (Common Platform Enumeration) string for WinRM.
// CPE format: cpe:2.3:a:microsoft:windows_remote_management:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field.
//
// Parameters:
//   - version: Windows OS version string (e.g., "10.0.17763"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildWinRMCPE(version string) string {
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:microsoft:windows_remote_management:%s:*:*:*:*:*:*:*", version)
}

// buildWinRMHTTPRequest constructs an HTTP/1.1 POST request with SOAP Identify envelope.
//
// Parameters:
//   - host: Target host:port (e.g., "localhost:5985")
//
// Returns:
//   - string: Complete HTTP request ready to send
func buildWinRMHTTPRequest(host string) string {
	soapBody := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>`
	contentLength := len(soapBody)

	return fmt.Sprintf(
		"POST /wsman HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: nerva/1.0\r\n"+
			"Content-Type: application/soap+xml;charset=UTF-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		host, contentLength, soapBody)
}

// extractHTTPBody extracts the body from an HTTP response by finding the
// header/body separator (\r\n\r\n).
//
// Parameters:
//   - response: Full HTTP response including headers
//
// Returns:
//   - []byte: Body portion of the response, or full response if no separator found
func extractHTTPBody(response []byte) []byte {
	// Look for "\r\n\r\n" which separates headers from body
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			if i+4 < len(response) {
				return response[i+4:]
			}
			return nil
		}
	}
	// No separator found, return original (edge case)
	return response
}

// detectWinRM performs WinRM detection using WS-Management SOAP protocol.
//
// Detection phases:
//  1. Send HTTP POST /wsman with SOAP Identify request (primary detection + enrichment)
//  2. Parse XML response for IdentifyResponse
//  3. Fallback: Check for 401 + Microsoft-HTTPAPI header
//
// Parameters:
//   - conn: Network connection to the target service
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//   - tls: Whether the connection uses TLS
//
// Returns:
//   - *plugins.Service: Service information if WinRM detected, nil otherwise
//   - error: Error details if detection failed
func detectWinRM(conn net.Conn, target plugins.Target, timeout time.Duration, tls bool) (*plugins.Service, error) {
	// Build host string for HTTP Host header
	host := fmt.Sprintf("%s:%d", target.Host, target.Address.Port())

	// Phase 1: Try /wsman endpoint with SOAP Identify
	identifyRequest := buildWinRMHTTPRequest(host)
	response, err := utils.SendRecv(conn, []byte(identifyRequest), timeout)
	if err != nil {
		return nil, err
	}

	// Check if we got a valid response
	if len(response) > 0 {
		// Extract XML body from HTTP response
		xmlBody := extractHTTPBody(response)

		// Try to parse as WinRM IdentifyResponse
		result := parseWinRMIdentifyResponse(xmlBody)
		if result != nil && result.detected {
			// WinRM detected via IdentifyResponse - we have full version info
			cpe := buildWinRMCPE(result.osVersion)
			payload := plugins.ServiceWinRM{
				ProductVendor:   result.productVendor,
				ProductVersion:  result.productVersion,
				ProtocolVersion: result.protocolVersion,
				OSVersion:       result.osVersion,
				AuthRequired:    false,
				CPEs:            []string{cpe},
			}

			if tls {
				return plugins.CreateServiceFrom(target, payload, true, result.osVersion, plugins.TCPTLS), nil
			}
			return plugins.CreateServiceFrom(target, payload, false, result.osVersion, plugins.TCP), nil
		}

		// Phase 2: Fallback - Check for 401 with Microsoft-HTTPAPI header
		statusCode := parseHTTPStatusCode(response)
		if statusCode == 401 && checkMicrosoftHTTPAPI(response) {
			// WinRM detected but auth required, no version info
			cpe := buildWinRMCPE("")
			payload := plugins.ServiceWinRM{
				AuthRequired: true,
				CPEs:         []string{cpe},
			}

			if tls {
				return plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS), nil
			}
			return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
		}
	}

	// Not WinRM
	return nil, nil
}

// WinRMPlugin methods (TCP - port 5985)

func (p *WinRMPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectWinRM(conn, target, timeout, false)
}

func (p *WinRMPlugin) PortPriority(port uint16) bool {
	return port == 5985
}

func (p *WinRMPlugin) Name() string {
	return WINRM
}

func (p *WinRMPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *WinRMPlugin) Priority() int {
	return 100
}

// WinRMTLSPlugin methods (TCPTLS - port 5986)

func (p *WinRMTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectWinRM(conn, target, timeout, true)
}

func (p *WinRMTLSPlugin) PortPriority(port uint16) bool {
	return port == 5986
}

func (p *WinRMTLSPlugin) Name() string {
	return WINRM
}

func (p *WinRMTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *WinRMTLSPlugin) Priority() int {
	return 101
}
