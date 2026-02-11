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
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestBuildGrafanaCPE tests CPE generation for Grafana
func TestBuildGrafanaCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with_version",
			version:  "10.4.1",
			expected: "cpe:2.3:a:grafana:grafana:10.4.1:*:*:*:*:*:*:*",
		},
		{
			name:     "empty_version_uses_wildcard",
			version:  "",
			expected: "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*",
		},
		{
			name:     "old_version",
			version:  "9.5.2",
			expected: "cpe:2.3:a:grafana:grafana:9.5.2:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildGrafanaCPE(tt.version)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// Mock HTTP response builders for testing

// buildMockGrafanaHealthResponse creates a mock HTTP response from Grafana /api/health
func buildMockGrafanaHealthResponse(version string) []byte {
	jsonBody := fmt.Sprintf(`{"commit":"abc123def","database":"ok","version":"%s"}`, version)

	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json; charset=UTF-8\r\n" +
		"\r\n" +
		jsonBody

	return []byte(httpResponse)
}

// buildMock404Response creates a mock HTTP 404 response
func buildMock404Response() []byte {
	httpResponse := "HTTP/1.1 404 Not Found\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html><body><h1>404 Not Found</h1></body></html>"

	return []byte(httpResponse)
}

// buildMockInvalidJSONResponse creates a mock response with invalid JSON
func buildMockInvalidJSONResponse() []byte {
	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		"{invalid json}"

	return []byte(httpResponse)
}

// buildMockMissingFieldsResponse creates a mock response without required fields
func buildMockMissingFieldsResponse() []byte {
	jsonBody := `{"commit":"abc123"}`

	httpResponse := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		jsonBody

	return []byte(httpResponse)
}

// buildMockEmptyResponse creates an empty mock response
func buildMockEmptyResponse() []byte {
	return []byte("")
}

// TestPluginMetadata tests plugin metadata methods
func TestGrafanaPluginMetadata(t *testing.T) {
	plugin := &GrafanaPlugin{}

	assert.Equal(t, "grafana", plugin.Name())
	assert.Equal(t, 100, plugin.Priority())
	assert.True(t, plugin.PortPriority(3000))
	assert.False(t, plugin.PortPriority(8080))
}

// TestGrafanaTLSPluginMetadata tests TLS plugin metadata methods
func TestGrafanaTLSPluginMetadata(t *testing.T) {
	plugin := &GrafanaTLSPlugin{}

	assert.Equal(t, "grafana", plugin.Name())
	assert.Equal(t, 101, plugin.Priority())
	assert.True(t, plugin.PortPriority(3000))
	assert.False(t, plugin.PortPriority(8080))
}

// TestDetectGrafana tests the core detection logic using net.Pipe mocked connections
func TestDetectGrafana(t *testing.T) {
	tests := []struct {
		name         string
		response     []byte
		wantVersion  string
		wantDetected bool
		wantErr      bool
	}{
		{
			name:         "valid_grafana_10x",
			response:     buildMockGrafanaHealthResponse("10.4.1"),
			wantVersion:  "10.4.1",
			wantDetected: true,
		},
		{
			name:         "valid_grafana_9x",
			response:     buildMockGrafanaHealthResponse("9.5.2"),
			wantVersion:  "9.5.2",
			wantDetected: true,
		},
		{
			name:         "valid_grafana_8x",
			response:     buildMockGrafanaHealthResponse("8.2.0"),
			wantVersion:  "8.2.0",
			wantDetected: true,
		},
		{
			name:         "non_200_response",
			response:     buildMock404Response(),
			wantDetected: false,
		},
		{
			name:         "invalid_json",
			response:     buildMockInvalidJSONResponse(),
			wantDetected: false,
		},
		{
			name:         "missing_fields",
			response:     buildMockMissingFieldsResponse(),
			wantDetected: false,
		},
		{
			name:    "empty_response",
			response: buildMockEmptyResponse(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()

			go func() {
				defer server.Close()
				buf := make([]byte, 4096)
				server.Read(buf)
				server.Write(tt.response)
			}()

			version, detected, err := detectGrafana(client, 5*time.Second)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantDetected, detected)
			if tt.wantDetected {
				assert.Equal(t, tt.wantVersion, version)
			}
		})
	}
}
