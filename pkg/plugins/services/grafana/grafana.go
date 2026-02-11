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

package grafana

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

/*
Grafana Fingerprinting via /api/health Endpoint

This plugin implements Grafana fingerprinting using the HTTP /api/health endpoint.
Grafana exposes health information at /api/health which includes version, database
status, and commit information.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is Grafana):
    - HTTP GET request to /api/health endpoint
    - Returns JSON response with health information
    - Must contain all three fields: database, version, commit
    - Distinguishes from other services by requiring all fields

  PHASE 2 - ENRICHMENT (extracts version information):
    - Version available directly in JSON response: version
    - Format: X.Y.Z (semantic versioning)
    - Available in all Grafana versions that expose /api/health

Expected JSON Response Structure:
{
  "commit": "abc123def456",
  "database": "ok",
  "version": "10.4.1"
}

Version Compatibility:
  - Grafana 5.x+: /api/health endpoint available
  - Earlier versions may not expose this endpoint consistently
*/

const (
	GRAFANA              = "grafana"
	DefaultGrafanaPort   = 3000
)

// grafanaHealthResponse represents the JSON response from Grafana /api/health endpoint
type grafanaHealthResponse struct {
	Database string `json:"database"`
	Version  string `json:"version"`
	Commit   string `json:"commit"`
}

type GrafanaPlugin struct{}
type GrafanaTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&GrafanaPlugin{})
	plugins.RegisterPlugin(&GrafanaTLSPlugin{})
}

// detectGrafana performs HTTP detection of Grafana service.
// Returns version string (empty if not found) and detection success boolean.
func detectGrafana(conn net.Conn, timeout time.Duration) (string, bool, error) {
	// Build HTTP GET request to /api/health endpoint
	httpRequest := "GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

	// Send HTTP request and receive response
	response, err := utils.SendRecv(conn, []byte(httpRequest), timeout)
	if err != nil {
		return "", false, err
	}
	if len(response) == 0 {
		return "", false, &utils.InvalidResponseError{Service: GRAFANA}
	}

	// Parse HTTP response
	responseStr := string(response)

	// Check for HTTP 200 OK status
	if !strings.Contains(responseStr, "HTTP/1.1 200") && !strings.Contains(responseStr, "HTTP/1.0 200") {
		// Not a successful response, not Grafana
		return "", false, nil
	}

	// Extract JSON body from HTTP response
	// HTTP response format: headers\r\n\r\nbody
	bodyStart := strings.Index(responseStr, "\r\n\r\n")
	if bodyStart == -1 {
		return "", false, &utils.InvalidResponseError{Service: GRAFANA}
	}
	jsonBody := responseStr[bodyStart+4:]

	// Parse JSON response
	var healthResp grafanaHealthResponse
	err = json.Unmarshal([]byte(jsonBody), &healthResp)
	if err != nil {
		// Not valid JSON or not Grafana format
		return "", false, nil
	}

	// Primary detection: Check for all three required fields
	if healthResp.Database == "" || healthResp.Version == "" || healthResp.Commit == "" {
		// Missing required fields, not Grafana
		return "", false, nil
	}

	// Successfully detected Grafana with version
	return healthResp.Version, true, nil
}

// buildGrafanaCPE generates a CPE (Common Platform Enumeration) string for Grafana.
// CPE format: cpe:2.3:a:grafana:grafana:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match Wappalyzer/RMI/FTP
// plugin behavior and enable asset inventory use cases.
func buildGrafanaCPE(version string) string {
	// Grafana product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:grafana:grafana:%s:*:*:*:*:*:*:*", version)
}

func (p *GrafanaPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := detectGrafana(conn, timeout)
	if err != nil {
		return nil, err
	}
	if !detected {
		return nil, nil
	}

	// Grafana detected - create service payload
	cpe := buildGrafanaCPE(version)
	payload := plugins.ServiceGrafana{
		CPEs: []string{cpe},
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *GrafanaPlugin) PortPriority(port uint16) bool {
	return port == DefaultGrafanaPort
}

func (p *GrafanaPlugin) Name() string {
	return GRAFANA
}

func (p *GrafanaPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *GrafanaPlugin) Priority() int {
	return 100
}

// GrafanaTLSPlugin implements TCPTLS variant
func (p *GrafanaTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := detectGrafana(conn, timeout)
	if err != nil {
		return nil, err
	}
	if !detected {
		return nil, nil
	}

	// Grafana detected - create service payload
	cpe := buildGrafanaCPE(version)
	payload := plugins.ServiceGrafana{
		CPEs: []string{cpe},
	}

	return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
}

func (p *GrafanaTLSPlugin) PortPriority(port uint16) bool {
	return port == DefaultGrafanaPort
}

func (p *GrafanaTLSPlugin) Name() string {
	return GRAFANA
}

func (p *GrafanaTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *GrafanaTLSPlugin) Priority() int {
	return 101
}
