package main

import (
	"bytes"
	"errors"
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

func TestParseArgsACSFlags(t *testing.T) {
	acs, req, err := parseArgs([]string{
		"--acs-config=/tmp/nsuacsrc",
		"--acs-section", "prod",
		"--acs-account=acct",
		"--acs-key", "key",
		"--acs-action", "version=1&action=dir",
		"--acs-sign-version=4",
		"-s",
		"https://example.com/123/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if acs.ConfigPath != "/tmp/nsuacsrc" || !acs.ConfigPathSet {
		t.Fatalf("config path = %q set=%v", acs.ConfigPath, acs.ConfigPathSet)
	}
	if acs.Section != "prod" || !acs.SectionSet {
		t.Fatalf("section = %q set=%v", acs.Section, acs.SectionSet)
	}
	if acs.Account != "acct" || acs.Key != "key" || acs.Action != "version=1&action=dir" {
		t.Fatalf("acs = %+v", acs)
	}
	if acs.SignVersion != 4 || !acs.SignVersionSet {
		t.Fatalf("sign version = %d set=%v", acs.SignVersion, acs.SignVersionSet)
	}
	if !req.Silent || req.URL != "https://example.com/123/" {
		t.Fatalf("req = %+v", req)
	}

	acs, _, err = parseArgs([]string{
		"--acs-action=version=1&action=stat",
		"https://example.com/123/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if acs.Action != "version=1&action=stat" {
		t.Fatalf("inline action = %q", acs.Action)
	}
}

func TestParseArgsHelpAndUnknownACSFlag(t *testing.T) {
	if _, _, err := parseArgs([]string{"--help"}); !errors.Is(err, errHelp) {
		t.Fatalf("help err = %v", err)
	}
	_, _, err := parseArgs([]string{"--acs-unknown", "value", "https://example.com/123/"})
	if err == nil || !strings.Contains(err.Error(), "unknown flag: --acs-unknown") {
		t.Fatalf("unknown flag err = %v", err)
	}
}

func TestParseArgsDoubleDashKeepsCurlArgs(t *testing.T) {
	acs, req, err := parseArgs([]string{
		"--acs-action", "version=1&action=dir",
		"--",
		"--compressed",
		"https://example.com/123/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if acs.Action != "version=1&action=dir" {
		t.Fatalf("action = %q", acs.Action)
	}
	if req.URL != "https://example.com/123/" {
		t.Fatalf("url = %q", req.URL)
	}
	if got := strings.Join(req.Args, " "); got != "-- --compressed https://example.com/123/" {
		t.Fatalf("curl args = %q", got)
	}
}

func TestValidationRejectsMissingAndDuplicateHeaders(t *testing.T) {
	for _, tc := range []struct {
		name       string
		headerArgs []string
		want       string
	}{
		{
			name:       "short separate auth data",
			headerArgs: []string{"-H", "X-Akamai-ACS-Auth-Data: nope"},
			want:       "X-Akamai-ACS-Auth-Data",
		},
		{
			name:       "short attached auth sign",
			headerArgs: []string{"-HX-Akamai-ACS-Auth-Sign: nope"},
			want:       "X-Akamai-ACS-Auth-Sign",
		},
		{
			name:       "long separate action",
			headerArgs: []string{"--header", "X-Akamai-ACS-Action: version=1&action=dir"},
			want:       "X-Akamai-ACS-Action",
		},
		{
			name:       "long inline auth data",
			headerArgs: []string{"--header=X-Akamai-ACS-Auth-Data: nope"},
			want:       "X-Akamai-ACS-Auth-Data",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{
				"--acs-account", "acct",
				"--acs-key", "key",
				"--acs-action", "version=1&action=dir",
			}
			args = append(args, tc.headerArgs...)
			args = append(args, "https://example.com/123/")
			acs, req, err := parseArgs(args)
			if err != nil {
				t.Fatal(err)
			}
			err = validateRequest(acs, req, credentials{Account: "acct", Key: "key"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected duplicate header error containing %q, got %v", tc.want, err)
			}
		})
	}

	acs, req, err := parseArgs([]string{
		"--acs-account", "acct",
		"--acs-key", "key",
		"--acs-action", "version=1&action=dir",
		"https://example.com/123/",
	})
	if err != nil {
		t.Fatal(err)
	}
	acs.Action = "action=dir"
	err = validateRequest(acs, req, credentials{Account: "acct", Key: "key"})
	if err == nil || !strings.Contains(err.Error(), "version=1") {
		t.Fatalf("expected version error, got %v", err)
	}
}

func TestUnknownCurlOptionsPassThroughToCurlArgs(t *testing.T) {
	_, req, err := parseArgs([]string{
		"--compressed",
		"--connect-timeout", "10",
		"--retry=3",
		"--user-agent", "nsucurl-test",
		"--location",
		"https://example.com/first",
		"https://example.com/123/file",
	})
	if err != nil {
		t.Fatal(err)
	}
	if req.URL != "https://example.com/123/file" {
		t.Fatalf("url = %q", req.URL)
	}
	for _, want := range []string{"--compressed", "--connect-timeout", "--retry=3", "--user-agent", "--location"} {
		if !contains(req.UnsupportedArgs, want) {
			t.Fatalf("unsupported args = %#v, missing %q", req.UnsupportedArgs, want)
		}
	}

	got := buildCurlArgs(req, signedHeaders{
		Action:   "version=1&action=dir",
		AuthData: "data",
		AuthSign: "sign",
	})
	wantArgs := []string{
		"--compressed",
		"--connect-timeout", "10",
		"--retry=3",
		"--user-agent", "nsucurl-test",
		"--location",
		"https://example.com/first",
		"-H", "X-Akamai-ACS-Action: version=1&action=dir",
		"-H", "X-Akamai-ACS-Auth-Data: data",
		"-H", "X-Akamai-ACS-Auth-Sign: sign",
		"https://example.com/123/file",
	}
	if strings.Join(got, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Fatalf("curl args = %#v, want %#v", got, wantArgs)
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

func TestBuildCurlArgsAppendsHeadersWhenURLIsAbsent(t *testing.T) {
	got := buildCurlArgs(curlRequest{Args: []string{"--help"}}, signedHeaders{
		Action:   "version=1&action=dir",
		AuthData: "data",
		AuthSign: "sign",
	})
	wantSuffix := []string{
		"-H", "X-Akamai-ACS-Action: version=1&action=dir",
		"-H", "X-Akamai-ACS-Auth-Data: data",
		"-H", "X-Akamai-ACS-Auth-Sign: sign",
	}
	if strings.Join(got[1:], "\x00") != strings.Join(wantSuffix, "\x00") {
		t.Fatalf("curl args = %#v", got)
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

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestReadConfigLongLine(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nsuacsrc")
	// > 64KB line to verify scanner buffer handles long lines
	longVal := strings.Repeat("a", 70000)
	content := fmt.Sprintf("[default]\naccount = myaccount\nkey = %s\n", longVal)
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := readConfig(configPath)
	if err != nil {
		t.Fatalf("readConfig failed on long line: %v", err)
	}
	if cfg["default"]["account"] != "myaccount" {
		t.Fatalf("account = %q", cfg["default"]["account"])
	}
	if cfg["default"]["key"] != longVal {
		t.Fatalf("key length mismatch: got %d, want %d", len(cfg["default"]["key"]), len(longVal))
	}
}

func TestValidateRequestRejectsEmptyOrMissingPath(t *testing.T) {
	acs := acsOptions{Action: "version=1&action=dir", SignVersion: 5}
	creds := credentials{Account: "acc", Key: "key"}

	for _, invalidURL := range []string{
		"https://example-nsu.akamaihd.net",
		"https://example-nsu.akamaihd.net?foo=bar",
	} {
		req := curlRequest{URL: invalidURL}
		err := validateRequest(acs, req, creds)
		if err == nil {
			t.Errorf("validateRequest should have failed for %q", invalidURL)
		}
	}
}

func TestBuildCurlArgsWithURLInOptionArgument(t *testing.T) {
	// e.g. -e / --referer passing an http URL as an option argument
	args := []string{
		"-s",
		"-e", "https://referer.example.com/page",
		"https://target-nsu.akamaihd.net/123/file",
	}
	_, req, err := parseArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	if req.URL != "https://target-nsu.akamaihd.net/123/file" {
		t.Fatalf("req.URL = %q", req.URL)
	}
	got := buildCurlArgs(req, signedHeaders{
		Action:   "version=1&action=stat",
		AuthData: "data",
		AuthSign: "sign",
	})

	joined := strings.Join(got, "\x00")
	actionIdx := strings.Index(joined, "X-Akamai-ACS-Action")
	refererIdx := strings.Index(joined, "https://referer.example.com/page")
	targetIdx := strings.Index(joined, "https://target-nsu.akamaihd.net/123/file")

	if refererIdx < 0 || actionIdx < 0 || targetIdx < 0 {
		t.Fatalf("missing elements in buildCurlArgs: %#v", got)
	}
	if actionIdx < refererIdx {
		t.Fatalf("headers were mistakenly inserted before referer argument: %#v", got)
	}
	if actionIdx > targetIdx {
		t.Fatalf("headers were not inserted before target URL: %#v", got)
	}
}

func TestDryRunFlag(t *testing.T) {
	args := []string{
		"--acs-account", "my-account",
		"--acs-key", "my-key",
		"--acs-action", "version=1&action=dir",
		"--dry-run",
		"-s",
		"https://example-nsu.akamaihd.net/123/",
	}
	var stdout, stderr bytes.Buffer
	code := run(args, nil, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run exited with code %d, stderr=%q", code, stderr.String())
	}
	out := stdout.String()
	if !strings.HasPrefix(out, "curl ") {
		t.Fatalf("expected output to start with 'curl ', got: %q", out)
	}
	if !strings.Contains(out, "X-Akamai-ACS-Action: version=1&action=dir") {
		t.Fatalf("output missing action header: %q", out)
	}
	if !strings.Contains(out, "X-Akamai-ACS-Auth-Sign:") {
		t.Fatalf("output missing auth sign header: %q", out)
	}
	if !strings.Contains(out, "https://example-nsu.akamaihd.net/123/") {
		t.Fatalf("output missing target URL: %q", out)
	}
}
