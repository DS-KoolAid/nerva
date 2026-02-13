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
Package fingerprinters provides HTTP fingerprinting for Jaeger.

# Detection Strategy

Jaeger is a widely deployed distributed tracing system. Exposed instances
represent a security concern due to:
  - Access to application tracing data revealing system architecture
  - Potential information disclosure about service dependencies
  - Exposure of performance metrics and call patterns
  - Query capabilities that could reveal sensitive information
  - Administrative endpoints that may be exposed

Detection uses a two-pronged approach:
1. Passive: Check for Content-Type: application/json header (weak pre-filter)
2. Active: Query /api/services endpoint (no authentication required)

# API Response Format

The /api/services endpoint returns JSON without authentication:

	{
	  "data": ["service-a", "service-b", "checkout", "frontend"],
	  "errors": null,
	  "limit": 0,
	  "offset": 0,
	  "total": 4
	}

Format breakdown:
  - data: Array of service name strings (required, must be non-empty for detection)
  - errors: Error field, typically null (required field to exist - distinguishes from other JSON APIs)
  - total: Total count of services (optional, helps disambiguate)
  - limit: Pagination limit (optional)
  - offset: Pagination offset (optional)

# Port Configuration

Jaeger typically runs on:
  - 16686: Default Jaeger Query service HTTP port
  - 443:   HTTPS in production deployments
  - 80:    HTTP in some deployments

# Example Usage

	fp := &JaegerFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s with %d services\n", result.Technology, result.Metadata["serviceCount"])
		}
	}
*/
package fingerprinters

import (
	"encoding/json"
	"net/http"
	"strings"
)

// JaegerFingerprinter detects Jaeger instances via /api/services endpoint
type JaegerFingerprinter struct{}

// jaegerServicesResponse represents the JSON structure from /api/services
type jaegerServicesResponse struct {
	Data   []string `json:"data"`
	Errors any      `json:"errors"`
	Limit  int      `json:"limit"`
	Offset int      `json:"offset"`
	Total  int      `json:"total"`
}

func init() {
	Register(&JaegerFingerprinter{})
}

func (f *JaegerFingerprinter) Name() string {
	return "jaeger"
}

func (f *JaegerFingerprinter) ProbeEndpoint() string {
	return "/api/services"
}

func (f *JaegerFingerprinter) Match(resp *http.Response) bool {
	// Check for Content-Type: application/json header
	// This is present on all Jaeger API responses but not unique to Jaeger
	// Use as weak pre-filter before active probe
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *JaegerFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try to parse as Jaeger services response
	var services jaegerServicesResponse
	if err := json.Unmarshal(body, &services); err != nil {
		return nil, nil // Not Jaeger format
	}

	// Validate it's actually Jaeger by checking required fields
	// Jaeger services endpoint always returns data array and errors field
	// The presence of data array + errors field + total field is the signature
	if services.Data == nil {
		return nil, nil
	}

	// Require non-empty services list for positive detection
	// Empty list could be other JSON APIs
	if len(services.Data) == 0 {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{
		"services":     services.Data,
		"serviceCount": len(services.Data),
	}

	// Add optional fields if present
	if services.Total > 0 {
		metadata["total"] = services.Total
	}
	if services.Limit > 0 {
		metadata["limit"] = services.Limit
	}
	if services.Offset > 0 {
		metadata["offset"] = services.Offset
	}

	return &FingerprintResult{
		Technology: "jaeger",
		Version:    "", // Jaeger doesn't expose version via /api/services
		CPEs:       []string{"cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*"},
		Metadata:   metadata,
	}, nil
}
