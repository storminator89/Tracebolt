//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"localrmm/internal/lanconfig"
	"net/http"
	"strings"
	"time"
)

const completeMVPOperatorReadLimit = 192 << 10

type completeMVPOperatorReadResult struct {
	failure string
	retried bool
}

// This is only the native acceptance client's GET contract. Production returns
// explicit bounded backpressure while its existing maintenance admission is
// occupied. One exact storage_busy retry retains the original five-second read
// deadline and caller context; POSTs, all other statuses and invalid DTOs fail.
func completeMVPOperatorGet(ctx context.Context, client *http.Client, origin, path string, out any, wait func(context.Context, time.Duration) error) completeMVPOperatorReadResult {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := completeMVPOperatorReadResult{}
	failed := func(category string) completeMVPOperatorReadResult { result.failure = category; return result }
	for attempt := 0; attempt < 2; attempt++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+path, nil)
		if err != nil {
			return failed("request")
		}
		response, err := client.Do(request)
		if err != nil {
			if ctx.Err() != nil {
				return failed("deadline")
			}
			return failed("transport")
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, completeMVPOperatorReadLimit+1))
		response.Body.Close()
		if ctx.Err() != nil {
			clear(raw)
			return failed("deadline")
		}
		if readErr != nil {
			clear(raw)
			return failed("body")
		}
		if len(raw) > completeMVPOperatorReadLimit {
			clear(raw)
			return failed("oversize")
		}
		if response.StatusCode == http.StatusOK {
			err = json.Unmarshal(raw, out)
			clear(raw)
			if err != nil {
				return failed("decode")
			}
			return result
		}
		retry := attempt == 0 && response.StatusCode == http.StatusTooManyRequests && completeMVPStorageBackoff(response.Header) && completeMVPStorageBusy(raw)
		clear(raw)
		if !retry {
			return failed(completeMVPOperatorStatus(response.StatusCode))
		}
		result.retried = true
		if wait(ctx, 2*time.Second) != nil {
			return failed("deadline")
		}
		if ctx.Err() != nil {
			return failed("deadline")
		}
	}
	return failed("http_429")
}

// Match the existing strict-object pattern: exactly one outer error member and
// exact, non-null string fields inside it. Ambiguous error codes cannot retry.
func completeMVPStorageBusy(raw []byte) bool {
	if len(raw) > 4096 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	key, err := decoder.Token()
	if err != nil || key != "error" {
		return false
	}
	var body json.RawMessage
	if decoder.Decode(&body) != nil {
		return false
	}
	defer clear(body)
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return false
	}
	if _, err = decoder.Token(); err != io.EOF {
		return false
	}
	var value struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	return lanconfig.StrictObject(body, &value, "code", "message") == nil && value.Code == "storage_busy" && value.Message != ""
}

func completeMVPStorageBackoff(header http.Header) bool {
	count := 0
	for name, values := range header {
		if !strings.EqualFold(name, "Retry-After") {
			continue
		}
		for _, value := range values {
			count++
			if count != 1 || value != "2" {
				return false
			}
		}
	}
	return count == 1
}

func completeMVPOperatorWait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func completeMVPOperatorStatus(status int) string {
	switch status {
	case 400:
		return "http_400"
	case 401:
		return "http_401"
	case 403:
		return "http_403"
	case 404:
		return "http_404"
	case 409:
		return "http_409"
	case 429:
		return "http_429"
	case 503:
		return "http_503"
	default:
		return "http_other"
	}
}

// Never include paths, device IDs, bodies, decoder errors or transport text in
// native evidence. These finite route labels are owned by the test source.
func completeMVPOperatorResource(path string) string {
	if path == "/api/enrollment" {
		return "enrollment"
	}
	if path == "/api/devices" {
		return "devices"
	}
	parts := strings.Split(path, "/")
	if len(parts) < 5 || parts[1] != "api" || parts[2] != "devices" {
		return "other"
	}
	if len(parts) == 5 && parts[4] == "operational" {
		return "operational"
	}
	if len(parts) == 6 && parts[4] == "inventory" {
		switch parts[5] {
		case "system":
			return "system"
		case "packages":
			return "packages"
		case "endpoint-identity":
			return "endpoint_identity"
		case "overview":
			return "overview"
		}
	}
	return "other"
}

type completeMVPOperatorTransport func(*http.Request) (*http.Response, error)

func (f completeMVPOperatorTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
