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

package fingerprinters

import (
	"net/http"
	"testing"
)

// --- SwaggerV2ApiDocsFingerprinter tests ---

func TestSwaggerV2ApiDocsFingerprinter_Name(t *testing.T) {
	fp := &SwaggerV2ApiDocsFingerprinter{}
	if got := fp.Name(); got != "swagger-v2-api-docs" {
		t.Errorf("Name() = %q, want %q", got, "swagger-v2-api-docs")
	}
}

func TestSwaggerV2ApiDocsFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SwaggerV2ApiDocsFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/v2/api-docs" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/v2/api-docs")
	}
}

func TestSwaggerV2ApiDocsFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "application/json returns true",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "application/json with charset returns true",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "text/html returns false",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "empty Content-Type returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SwaggerV2ApiDocsFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSwaggerV2ApiDocsFingerprinter_Fingerprint_TypicalResponse(t *testing.T) {
	// Real Swagger 2.0 spec from Spring Boot
	body := `{
		"swagger": "2.0",
		"info": {
			"title": "My API",
			"version": "1.0.0"
		},
		"paths": {
			"/users": {
				"get": {
					"summary": "Get users"
				}
			}
		}
	}`

	fp := &SwaggerV2ApiDocsFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "swagger" {
		t.Errorf("Technology = %q, want %q", result.Technology, "swagger")
	}
	if result.Version != "2.0" {
		t.Errorf("Version = %q, want %q", result.Version, "2.0")
	}
	if len(result.CPEs) != 1 {
		t.Fatalf("CPEs count = %d, want 1", len(result.CPEs))
	}
	if result.CPEs[0] != "cpe:2.3:a:smartbear:swagger:2.0:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q, want %q", result.CPEs[0], "cpe:2.3:a:smartbear:swagger:2.0:*:*:*:*:*:*:*")
	}

	// Check metadata
	apiTitle, ok := result.Metadata["api_title"].(string)
	if !ok || apiTitle != "My API" {
		t.Errorf("api_title = %q, want %q", apiTitle, "My API")
	}

	apiVersion, ok := result.Metadata["api_version"].(string)
	if !ok || apiVersion != "1.0.0" {
		t.Errorf("api_version = %q, want %q", apiVersion, "1.0.0")
	}

	specVersion, ok := result.Metadata["spec_version"].(string)
	if !ok || specVersion != "2.0" {
		t.Errorf("spec_version = %q, want %q", specVersion, "2.0")
	}

	detectionMethod, ok := result.Metadata["detection_method"].(string)
	if !ok || detectionMethod != "openapi_spec" {
		t.Errorf("detection_method = %q, want %q", detectionMethod, "openapi_spec")
	}

	endpoint, ok := result.Metadata["endpoint"].(string)
	if !ok || endpoint != "/v2/api-docs" {
		t.Errorf("endpoint = %q, want %q", endpoint, "/v2/api-docs")
	}
}

func TestSwaggerV2ApiDocsFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Not JSON",
			body: `This is not JSON`,
		},
		{
			name: "Empty JSON object",
			body: `{}`,
		},
		{
			name: "Missing swagger field",
			body: `{"info": {"title": "API", "version": "1.0"}}`,
		},
		{
			name: "Wrong swagger version",
			body: `{"swagger": "3.0", "info": {"title": "API", "version": "1.0"}}`,
		},
		{
			name: "OpenAPI 3 spec",
			body: `{"openapi": "3.0.0", "info": {"title": "API", "version": "1.0"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SwaggerV2ApiDocsFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil for input: %s", result, tt.name)
			}
		})
	}
}

// --- SwaggerV3ApiDocsFingerprinter tests ---

func TestSwaggerV3ApiDocsFingerprinter_Name(t *testing.T) {
	fp := &SwaggerV3ApiDocsFingerprinter{}
	if got := fp.Name(); got != "swagger-v3-api-docs" {
		t.Errorf("Name() = %q, want %q", got, "swagger-v3-api-docs")
	}
}

func TestSwaggerV3ApiDocsFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SwaggerV3ApiDocsFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/v3/api-docs" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/v3/api-docs")
	}
}

func TestSwaggerV3ApiDocsFingerprinter_Fingerprint_TypicalResponse(t *testing.T) {
	// Real OpenAPI 3.0.1 spec from Spring Boot
	body := `{
		"openapi": "3.0.1",
		"info": {
			"title": "My API",
			"version": "v1.0.0"
		},
		"paths": {
			"/users": {
				"get": {
					"summary": "Get users"
				}
			}
		}
	}`

	fp := &SwaggerV3ApiDocsFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "openapi" {
		t.Errorf("Technology = %q, want %q", result.Technology, "openapi")
	}
	if result.Version != "3.0.1" {
		t.Errorf("Version = %q, want %q", result.Version, "3.0.1")
	}
	if len(result.CPEs) != 1 {
		t.Fatalf("CPEs count = %d, want 1", len(result.CPEs))
	}
	if result.CPEs[0] != "cpe:2.3:a:openapis:openapi:3.0.1:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q, want %q", result.CPEs[0], "cpe:2.3:a:openapis:openapi:3.0.1:*:*:*:*:*:*:*")
	}

	// Check metadata
	specVersion, ok := result.Metadata["spec_version"].(string)
	if !ok || specVersion != "3.0.1" {
		t.Errorf("spec_version = %q, want %q", specVersion, "3.0.1")
	}

	endpoint, ok := result.Metadata["endpoint"].(string)
	if !ok || endpoint != "/v3/api-docs" {
		t.Errorf("endpoint = %q, want %q", endpoint, "/v3/api-docs")
	}
}

// --- SwaggerJsonFingerprinter tests ---

func TestSwaggerJsonFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SwaggerJsonFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/swagger.json" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/swagger.json")
	}
}

// --- SwaggerJsonFingerprinter tests ---

func TestSwaggerJsonFingerprinter_Name(t *testing.T) {
	fp := &SwaggerJsonFingerprinter{}
	if got := fp.Name(); got != "swagger-json" {
		t.Errorf("Name() = %q, want %q", got, "swagger-json")
	}
}

func TestSwaggerJsonFingerprinter_Match(t *testing.T) {
	fp := &SwaggerJsonFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")
	if !fp.Match(resp) {
		t.Error("Match() should return true for application/json")
	}
}

func TestSwaggerJsonFingerprinter_Fingerprint(t *testing.T) {
	body := `{"swagger": "2.0", "info": {"title": "Test API", "version": "1.0"}}`
	fp := &SwaggerJsonFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}
	if result.Technology != "swagger" {
		t.Errorf("Technology = %q, want %q", result.Technology, "swagger")
	}
	endpoint := result.Metadata["endpoint"].(string)
	if endpoint != "/swagger.json" {
		t.Errorf("endpoint = %q, want %q", endpoint, "/swagger.json")
	}
}

// --- OpenApiJsonFingerprinter tests ---

func TestOpenApiJsonFingerprinter_Name(t *testing.T) {
	fp := &OpenApiJsonFingerprinter{}
	if got := fp.Name(); got != "openapi-json" {
		t.Errorf("Name() = %q, want %q", got, "openapi-json")
	}
}

func TestOpenApiJsonFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &OpenApiJsonFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/openapi.json" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/openapi.json")
	}
}

func TestOpenApiJsonFingerprinter_Match(t *testing.T) {
	fp := &OpenApiJsonFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")
	if !fp.Match(resp) {
		t.Error("Match() should return true for application/json")
	}
}

func TestOpenApiJsonFingerprinter_Fingerprint(t *testing.T) {
	body := `{"openapi": "3.0.2", "info": {"title": "Test API", "version": "2.0"}}`
	fp := &OpenApiJsonFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}
	if result.Technology != "openapi" {
		t.Errorf("Technology = %q, want %q", result.Technology, "openapi")
	}
	endpoint := result.Metadata["endpoint"].(string)
	if endpoint != "/openapi.json" {
		t.Errorf("endpoint = %q, want %q", endpoint, "/openapi.json")
	}
}

// --- SwaggerNetFingerprinter tests ---

func TestSwaggerNetFingerprinter_Name(t *testing.T) {
	fp := &SwaggerNetFingerprinter{}
	if got := fp.Name(); got != "swagger-net" {
		t.Errorf("Name() = %q, want %q", got, "swagger-net")
	}
}

func TestSwaggerNetFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SwaggerNetFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/swagger/v1/swagger.json" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/swagger/v1/swagger.json")
	}
}

func TestSwaggerNetFingerprinter_Match(t *testing.T) {
	fp := &SwaggerNetFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")
	if !fp.Match(resp) {
		t.Error("Match() should return true for application/json")
	}
}

func TestSwaggerNetFingerprinter_Fingerprint(t *testing.T) {
	body := `{"openapi": "3.0.1", "info": {"title": ".NET API", "version": "v1"}}`
	fp := &SwaggerNetFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}
	if result.Technology != "openapi" {
		t.Errorf("Technology = %q, want %q", result.Technology, "openapi")
	}
	framework := result.Metadata["framework"].(string)
	if framework != ".NET Swashbuckle" {
		t.Errorf("framework = %q, want %q", framework, ".NET Swashbuckle")
	}
	endpoint := result.Metadata["endpoint"].(string)
	if endpoint != "/swagger/v1/swagger.json" {
		t.Errorf("endpoint = %q, want %q", endpoint, "/swagger/v1/swagger.json")
	}
}

// --- SwaggerUIFingerprinter tests ---

func TestSwaggerUIFingerprinter_Name(t *testing.T) {
	fp := &SwaggerUIFingerprinter{}
	if got := fp.Name(); got != "swagger-ui" {
		t.Errorf("Name() = %q, want %q", got, "swagger-ui")
	}
}

func TestSwaggerUIFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SwaggerUIFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/swagger-ui.html" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/swagger-ui.html")
	}
}

func TestSwaggerUIFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "text/html returns true",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "text/html with charset returns true",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "application/json returns false",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "empty Content-Type returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SwaggerUIFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSwaggerUIFingerprinter_Fingerprint_TypicalResponse(t *testing.T) {
	// Real Swagger UI HTML page
	body := `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Swagger UI</title>
	<link rel="stylesheet" type="text/css" href="./swagger-ui.css" />
</head>
<body>
<div id="swagger-ui"></div>
<script src="./swagger-ui-bundle.js"></script>
<script>
window.onload = function() {
	const ui = SwaggerUIBundle({
		url: "/api/swagger.json",
		dom_id: '#swagger-ui'
	});
};
</script>
</body>
</html>`

	fp := &SwaggerUIFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "swagger-ui" {
		t.Errorf("Technology = %q, want %q", result.Technology, "swagger-ui")
	}
	if result.Version != "" {
		t.Errorf("Version = %q, want empty", result.Version)
	}
	if len(result.CPEs) != 1 {
		t.Fatalf("CPEs count = %d, want 1", len(result.CPEs))
	}
	if result.CPEs[0] != "cpe:2.3:a:smartbear:swagger:*:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q, want %q", result.CPEs[0], "cpe:2.3:a:smartbear:swagger:*:*:*:*:*:*:*:*")
	}

	detectionMethod, ok := result.Metadata["detection_method"].(string)
	if !ok || detectionMethod != "swagger_ui" {
		t.Errorf("detection_method = %q, want %q", detectionMethod, "swagger_ui")
	}

	endpoint, ok := result.Metadata["endpoint"].(string)
	if !ok || endpoint != "/swagger-ui.html" {
		t.Errorf("endpoint = %q, want %q", endpoint, "/swagger-ui.html")
	}
}

func TestSwaggerUIFingerprinter_Fingerprint_MarkerCombinations(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "swagger-ui.css + swagger-ui-bundle.js",
			body: `<html><link href="swagger-ui.css"><script src="swagger-ui-bundle.js"></script></html>`,
			want: true,
		},
		{
			name: "SwaggerUIBundle in script",
			body: `<html><script>const ui = SwaggerUIBundle({url: "/api"});</script></html>`,
			want: true,
		},
		{
			name: "swagger-ui.css only",
			body: `<html><link href="swagger-ui.css"></html>`,
			want: false,
		},
		{
			name: "Empty HTML",
			body: `<html><body></body></html>`,
			want: false,
		},
		{
			name: "Generic API docs page",
			body: `<html><head><title>API Docs</title></head><body><h1>API Documentation</h1></body></html>`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SwaggerUIFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			resp.Header.Set("Content-Type", "text/html")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}

			if tt.want {
				if result == nil {
					t.Fatal("Fingerprint() returned nil, want result")
				}
				if result.Technology != "swagger-ui" {
					t.Errorf("Technology = %q, want %q", result.Technology, "swagger-ui")
				}
			} else {
				if result != nil {
					t.Errorf("Fingerprint() = %+v, want nil", result)
				}
			}
		})
	}
}

// --- Helper function tests ---

func TestBuildSwaggerCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:smartbear:swagger:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Version 2.0",
			version: "2.0",
			want:    "cpe:2.3:a:smartbear:swagger:2.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Version with special chars sanitized",
			version: "2.0; rm -rf /",
			want:    "cpe:2.3:a:smartbear:swagger:2.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildSwaggerCPE(tt.version); got != tt.want {
				t.Errorf("buildSwaggerCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildOpenAPICPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:openapis:openapi:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Version 3.0.1",
			version: "3.0.1",
			want:    "cpe:2.3:a:openapis:openapi:3.0.1:*:*:*:*:*:*:*",
		},
		{
			name:    "Version with special chars sanitized",
			version: "3.0.1; DROP TABLE",
			want:    "cpe:2.3:a:openapis:openapi:3.0.1:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildOpenAPICPE(tt.version); got != tt.want {
				t.Errorf("buildOpenAPICPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSanitizeVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Valid semver",
			input: "3.0.1",
			want:  "3.0.1",
		},
		{
			name:  "Valid with hyphen",
			input: "2.0-rc1",
			want:  "2.0-rc1",
		},
		{
			name:  "Malicious SQL injection",
			input: "3.0.1; DROP TABLE users",
			want:  "3.0.1",
		},
		{
			name:  "Path traversal",
			input: "../../etc/passwd",
			want:  "",
		},
		{
			name:  "XSS attempt",
			input: "<script>alert(1)</script>",
			want:  "",
		},
		{
			name:  "Empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeVersion(tt.input); got != tt.want {
				t.Errorf("sanitizeVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}
