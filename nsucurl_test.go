package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignRequestFixedValues(t *testing.T) {
	got, err := signRequest(signerInput{
		URL:         "https://example-nsu.akamaihd.net/123456/path/file.txt?x=1",
		Action:      "version=1&action=stat",
		Account:     "UploadAccountMedia",
		Key:         "secret",
		SignVersion: 5,
		Now:         time.Unix(1280000000, 0),
		UniqueID:    "382644692",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != "version=1&action=stat" {
		t.Fatalf("action = %q", got.Action)
	}
	wantData := "5, 0.0.0.0, 0.0.0.0, 1280000000, 382644692, UploadAccountMedia"
	if got.AuthData != wantData {
		t.Fatalf("auth data = %q, want %q", got.AuthData, wantData)
	}
	wantSign := "vWLe3GX1o3kDeT3RNyTPAuezulRuCc4GJ82ENEeDzGk="
	if got.AuthSign != wantSign {
		t.Fatalf("auth sign = %q, want %q", got.AuthSign, wantSign)
	}
}

func TestResolveCredentialsPrecedence(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nsuacsrc")
	if err := os.WriteFile(configPath, []byte("[default]\naccount = file-account\nkey = file-key\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := resolveCredentials(acsOptions{
		ConfigPath: configPath,
		Section:    "default",
		Account:    "cli-account",
	}, map[string]string{
		"NETSTORAGE_ACCOUNT": "env-account",
		"NETSTORAGE_KEY":     "env-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Account != "cli-account" || got.Key != "env-key" {
		t.Fatalf("credentials = %+v", got)
	}

	got, err = resolveCredentials(acsOptions{
		ConfigPath: configPath,
		Section:    "default",
	}, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Account != "file-account" || got.Key != "file-key" {
		t.Fatalf("credentials from file = %+v", got)
	}
}

func TestResolveCredentialsConfigAndSectionPrecedence(t *testing.T) {
	dir := t.TempDir()
	cliConfig := filepath.Join(dir, "cli")
	envConfig := filepath.Join(dir, "env")
	if err := os.WriteFile(cliConfig, []byte("[cli]\naccount = cli-file-account\nkey = cli-file-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envConfig, []byte("[env]\naccount = env-file-account\nkey = env-file-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveCredentials(acsOptions{
		ConfigPath:    cliConfig,
		ConfigPathSet: true,
		Section:       "cli",
		SectionSet:    true,
	}, map[string]string{
		"NETSTORAGE_CONFIG":  envConfig,
		"NETSTORAGE_SECTION": "env",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Account != "cli-file-account" || got.Key != "cli-file-key" {
		t.Fatalf("credentials = %+v", got)
	}
}

func TestValidationRejectsMissingAndDuplicateHeaders(t *testing.T) {
	acs, req, err := parseArgs([]string{
		"--acs-account", "acct",
		"--acs-key", "key",
		"--acs-action", "version=1&action=dir",
		"-H", "X-Akamai-ACS-Auth-Data: nope",
		"https://example.com/123/",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = validateRequest(acs, req, credentials{Account: "acct", Key: "key"})
	if err == nil || !strings.Contains(err.Error(), "X-Akamai-ACS-Auth-Data") {
		t.Fatalf("expected duplicate auth header error, got %v", err)
	}

	acs.Action = "action=dir"
	req.AuthDataSeen = false
	err = validateRequest(acs, req, credentials{Account: "acct", Key: "key"})
	if err == nil || !strings.Contains(err.Error(), "version=1") {
		t.Fatalf("expected version error, got %v", err)
	}
}

func TestBuildCurlArgsInjectsHeadersBeforeURL(t *testing.T) {
	_, req, err := parseArgs([]string{
		"-s",
		"-X", "PUT",
		"--data-binary", "@file",
		"https://example.com/123/file",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := buildCurlArgs(req, signedHeaders{
		Action:   "version=1&action=upload",
		AuthData: "data",
		AuthSign: "sign",
	})
	joined := strings.Join(got, "\x00")
	actionIdx := strings.Index(joined, "X-Akamai-ACS-Action")
	urlIdx := strings.Index(joined, "https://example.com/123/file")
	if actionIdx < 0 || urlIdx < 0 || actionIdx > urlIdx {
		t.Fatalf("headers were not inserted before URL: %#v", got)
	}
}

func TestRunHTTPFallbackGETAndHeaders(t *testing.T) {
	var sawAction, sawData, sawSign string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAction = r.Header.Get("X-Akamai-ACS-Action")
		sawData = r.Header.Get("X-Akamai-ACS-Auth-Data")
		sawSign = r.Header.Get("X-Akamai-ACS-Auth-Sign")
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	_, req, err := parseArgs([]string{server.URL + "/123/path"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code, err := runHTTP(req, signedHeaders{Action: "version=1&action=dir", AuthData: "data", AuthSign: "sign"}, &out, &bytes.Buffer{})
	if err != nil || code != 0 {
		t.Fatalf("runHTTP code=%d err=%v", code, err)
	}
	if out.String() != "ok" {
		t.Fatalf("body = %q", out.String())
	}
	if sawAction != "version=1&action=dir" || sawData != "data" || sawSign != "sign" {
		t.Fatalf("headers action=%q data=%q sign=%q", sawAction, sawData, sawSign)
	}
}

func TestRunHTTPFallbackDataBinaryFile(t *testing.T) {
	dir := t.TempDir()
	bodyPath := filepath.Join(dir, "body.txt")
	if err := os.WriteFile(bodyPath, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method = %s", r.Method)
		}
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		if body.String() != "payload" {
			t.Errorf("body = %q", body.String())
		}
		fmt.Fprint(w, "uploaded")
	}))
	defer server.Close()

	_, req, err := parseArgs([]string{"-X", "PUT", "--data-binary", "@" + bodyPath, server.URL + "/123/file"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code, err := runHTTP(req, signedHeaders{Action: "version=1&action=upload", AuthData: "data", AuthSign: "sign"}, &out, &bytes.Buffer{})
	if err != nil || code != 0 {
		t.Fatalf("runHTTP code=%d err=%v", code, err)
	}
	if out.String() != "uploaded" {
		t.Fatalf("body = %q", out.String())
	}
}

func TestFallbackRejectsUnknownCurlArgs(t *testing.T) {
	_, req, err := parseArgs([]string{"--compressed", "https://example.com/123"})
	if err != nil {
		t.Fatal(err)
	}
	code, err := runHTTP(req, signedHeaders{}, &bytes.Buffer{}, &bytes.Buffer{})
	if code != 2 || err == nil || !strings.Contains(err.Error(), "--compressed") {
		t.Fatalf("code=%d err=%v", code, err)
	}
}
