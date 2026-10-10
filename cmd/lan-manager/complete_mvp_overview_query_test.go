//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const completeMVPOverviewQueryLimit = 256 << 10

type completeMVPOverviewQueryInput struct {
	Section      string `json:"section"`
	GenerationID string `json:"generationId"`
	Cursor       string `json:"cursor"`
	Search       string `json:"search"`
	Limit        int    `json:"limit"`
}

type completeMVPOverviewQueryResult struct {
	status        int
	failure       string
	busy, retried bool
}

// This test-only POST is a read of one pinned overview page. The route cannot
// select an authentication or mutation operation. Only exact documented storage
// backpressure permits one retry, within the original five-second deadline.
// Generic POSTs and production admission are unchanged.
func completeMVPOverviewQueryRead(ctx context.Context, client *http.Client, origin, device, csrf string, input completeMVPOverviewQueryInput, wait func(context.Context, time.Duration) error) (completeMVPOverviewPage, completeMVPOverviewQueryResult) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := completeMVPOverviewQueryResult{}
	failed := func(category string) (completeMVPOverviewPage, completeMVPOverviewQueryResult) {
		result.failure = category
		return completeMVPOverviewPage{}, result
	}
	requestRaw, err := json.Marshal(input)
	if err != nil {
		return failed("request")
	}
	defer clear(requestRaw)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/api/devices/"+device+"/inventory/overview/query", bytes.NewReader(requestRaw))
	if err != nil {
		return failed("request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	request.Header.Set("X-CSRF-Token", csrf)
	// Freeze the initial authenticated session as well as the request bytes.
	// A response cannot rotate the jar between these two reads. Retain the
	// caller's transport/TLS and timeout, and never follow a redirect.
	queryClient := *client
	queryClient.Jar = nil
	queryClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Jar != nil {
		for _, cookie := range client.Jar.Cookies(request.URL) {
			request.AddCookie(cookie)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		if ctx.Err() != nil {
			return failed("deadline")
		}
		attemptRequest := request.Clone(ctx)
		attemptRequest.Body = io.NopCloser(bytes.NewReader(requestRaw))
		attemptRequest.GetBody = nil
		result.status = 0
		result.busy = false
		response, err := queryClient.Do(attemptRequest)
		if err != nil {
			if ctx.Err() != nil {
				return failed("deadline")
			}
			return failed("transport")
		}
		result.status = response.StatusCode
		result.busy = false
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, completeMVPOverviewQueryLimit+1))
		response.Body.Close()
		if ctx.Err() != nil {
			clear(raw)
			return failed("deadline")
		}
		if readErr != nil {
			clear(raw)
			return failed("body")
		}
		if len(raw) > completeMVPOverviewQueryLimit {
			clear(raw)
			return failed("oversize")
		}
		if response.StatusCode == http.StatusOK {
			var page completeMVPOverviewPage
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&page) != nil {
				clear(raw)
				return failed("decode")
			}
			if decoder.Decode(new(any)) != io.EOF {
				clear(raw)
				return failed("trailing")
			}
			clear(raw)
			return page, result
		}
		result.busy = response.StatusCode == http.StatusTooManyRequests && completeMVPStorageBackoff(response.Header) && completeMVPStorageBusy(raw)
		clear(raw)
		if attempt != 0 || !result.busy {
			return failed("status")
		}
		result.retried = true
		if wait(ctx, 2*time.Second) != nil {
			return failed("deadline")
		}
	}
	return failed("status")
}

func completeMVPOverviewQuerySection(section string) string {
	if section == "processes" || section == "volumes" {
		return section
	}
	return "other"
}

// The only formatted fields are finite source-owned enums and a boolean. Never
// print response bodies, decoder/transport messages, routes, IDs or credentials.
func completeMVPOverviewQueryDiagnostic(section string, result completeMVPOverviewQueryResult) string {
	status := completeMVPOperatorStatus(result.status)
	if result.status == 0 {
		status = "none"
	} else if result.status == http.StatusOK {
		status = "http_200"
	}
	failure := "other"
	switch result.failure {
	case "request", "deadline", "transport", "body", "oversize", "decode", "trailing", "status":
		failure = result.failure
	}
	return fmt.Sprintf("complete operator overview query diagnostic: section=%s status=%s failure=%s storage_busy=%t", completeMVPOverviewQuerySection(section), status, failure, result.busy)
}
