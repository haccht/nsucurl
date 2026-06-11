package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

const (
	defaultConfigPath = "~/.nsuacsrc"
	defaultSection    = "default"
	defaultSignVer    = 5
)

var errHelp = errors.New("help requested")

type acsOptions struct {
	ConfigPath     string
	ConfigPathSet  bool
	Section        string
	SectionSet     bool
	Account        string
	Key            string
	Action         string
	SignVersion    int
	SignVersionSet bool
}

type curlRequest struct {
	Args             []string
	URL              string
	Method           string
	Headers          []string
	Data             *dataSpec
	Output           string
	IncludeHeaders   bool
	Silent           bool
	Head             bool
	UnsupportedArgs  []string
	UserHeaderNames  map[string]bool
	ActionHeaderSeen bool
	AuthDataSeen     bool
	AuthSignSeen     bool
}

type dataSpec struct {
	Value  string
	Binary bool
}

type credentials struct {
	Account string
	Key     string
}

type signerInput struct {
	URL         string
	Action      string
	Account     string
	Key         string
	SignVersion int
	Now         time.Time
	UniqueID    string
}

type signedHeaders struct {
	Action   string
	AuthData string
	AuthSign string
}

func run(args []string, environ []string, stdout, stderr io.Writer) int {
	code, err := runErr(args, environ, stdout, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "nsucurl:", err)
		return code
	}
	return code
}

func runErr(args []string, environ []string, stdout, stderr io.Writer) (int, error) {
	acs, req, err := parseArgs(args)
	if err != nil {
		if errors.Is(err, errHelp) {
			printUsage(stdout)
			return 0, nil
		}
		return 2, err
	}
	env := envMap(environ)
	creds, err := resolveCredentials(acs, env)
	if err != nil {
		return 2, err
	}
	if err := validateRequest(acs, req, creds); err != nil {
		return 2, err
	}
	uid, err := newUniqueID()
	if err != nil {
		return 1, err
	}
	headers, err := signRequest(signerInput{
		URL:         req.URL,
		Action:      acs.Action,
		Account:     creds.Account,
		Key:         creds.Key,
		SignVersion: acs.SignVersion,
		Now:         time.Now(),
		UniqueID:    uid,
	})
	if err != nil {
		return 2, err
	}

	if curlPath, err := exec.LookPath("curl"); err == nil {
		return runCurl(curlPath, req, headers, stdout, stderr)
	}
	return runHTTP(req, headers, stdout, stderr)
}

func parseArgs(args []string) (acsOptions, curlRequest, error) {
	acs := acsOptions{
		ConfigPath:  defaultConfigPath,
		Section:     defaultSection,
		SignVersion: defaultSignVer,
	}
	req := curlRequest{
		Method:          "GET",
		UserHeaderNames: map[string]bool{},
	}
	var acsArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			return acs, req, errHelp
		}
		if arg == "--" {
			req.Args = append(req.Args, args[i:]...)
			for _, rest := range args[i+1:] {
				if looksLikeURL(rest) {
					req.URL = rest
				}
			}
			break
		}
		if strings.HasPrefix(arg, "--acs-") {
			name, _, hasInline := splitLongOpt(arg)
			acsArgs = append(acsArgs, arg)
			if !hasInline && acsFlagTakesValue(name) && i+1 < len(args) {
				i++
				acsArgs = append(acsArgs, args[i])
			}
			continue
		}

		req.Args = append(req.Args, arg)
		if err := scanCurlArg(args, &i, &req); err != nil {
			return acs, req, err
		}
	}
	if err := parseACSFlags(acsArgs, &acs); err != nil {
		return acs, req, err
	}
	return acs, req, nil
}

func parseACSFlags(args []string, acs *acsOptions) error {
	fs := newACSFlagSet(acs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	acs.ConfigPathSet = fs.Changed("acs-config")
	acs.SectionSet = fs.Changed("acs-section")
	acs.SignVersionSet = fs.Changed("acs-sign-version")
	return nil
}

func newACSFlagSet(acs *acsOptions) *pflag.FlagSet {
	fs := pflag.NewFlagSet("nsucurl", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.SortFlags = false
	fs.StringVar(&acs.ConfigPath, "acs-config", defaultConfigPath, "credential file path")
	fs.StringVar(&acs.Section, "acs-section", defaultSection, "credential section")
	fs.StringVar(&acs.Account, "acs-account", "", "NetStorage upload account ID")
	fs.StringVar(&acs.Key, "acs-key", "", "NetStorage HTTP API key")
	fs.StringVar(&acs.Action, "acs-action", "", "X-Akamai-ACS-Action value")
	fs.IntVar(&acs.SignVersion, "acs-sign-version", defaultSignVer, "signature version")
	return fs
}

func acsFlagTakesValue(name string) bool {
	acs := acsOptions{
		ConfigPath:  defaultConfigPath,
		Section:     defaultSection,
		SignVersion: defaultSignVer,
	}
	flag := newACSFlagSet(&acs).Lookup(strings.TrimPrefix(name, "--"))
	return flag != nil && flag.NoOptDefVal == ""
}

func scanCurlArg(args []string, i *int, req *curlRequest) error {
	arg := args[*i]
	if looksLikeURL(arg) {
		req.URL = arg
		return nil
	}
	nextValue := func(name string) (string, error) {
		if *i+1 >= len(args) {
			return "", fmt.Errorf("%s requires a value", name)
		}
		*i++
		req.Args = append(req.Args, args[*i])
		return args[*i], nil
	}
	nextLong := func(name, value string, hasInline bool) (string, error) {
		if hasInline {
			return value, nil
		}
		return nextValue(name)
	}

	if strings.HasPrefix(arg, "--") {
		name, val, hasInline := splitLongOpt(arg)
		switch name {
		case "--request":
			v, err := nextLong(name, val, hasInline)
			req.Method = strings.ToUpper(v)
			return err
		case "--header":
			v, err := nextLong(name, val, hasInline)
			req.addHeader(v)
			return err
		case "--data", "--data-ascii":
			v, err := nextLong(name, val, hasInline)
			req.Data = &dataSpec{Value: v}
			if req.Method == "GET" {
				req.Method = "POST"
			}
			return err
		case "--data-binary":
			v, err := nextLong(name, val, hasInline)
			req.Data = &dataSpec{Value: v, Binary: true}
			if req.Method == "GET" {
				req.Method = "POST"
			}
			return err
		case "--head":
			req.Head = true
			req.Method = "HEAD"
			return nil
		case "--output":
			v, err := nextLong(name, val, hasInline)
			req.Output = v
			return err
		case "--include":
			req.IncludeHeaders = true
			return nil
		case "--silent":
			req.Silent = true
			return nil
		case "--verbose":
			req.UnsupportedArgs = append(req.UnsupportedArgs, arg)
			return nil
		default:
			req.UnsupportedArgs = append(req.UnsupportedArgs, arg)
			return nil
		}
	}

	switch {
	case arg == "-X":
		v, err := nextValue(arg)
		req.Method = strings.ToUpper(v)
		return err
	case strings.HasPrefix(arg, "-X") && len(arg) > 2:
		req.Method = strings.ToUpper(arg[2:])
		return nil
	case arg == "-H":
		v, err := nextValue(arg)
		req.addHeader(v)
		return err
	case strings.HasPrefix(arg, "-H") && len(arg) > 2:
		req.addHeader(arg[2:])
		return nil
	case arg == "-d":
		v, err := nextValue(arg)
		req.Data = &dataSpec{Value: v}
		if req.Method == "GET" {
			req.Method = "POST"
		}
		return err
	case strings.HasPrefix(arg, "-d") && len(arg) > 2:
		req.Data = &dataSpec{Value: arg[2:]}
		if req.Method == "GET" {
			req.Method = "POST"
		}
		return nil
	case arg == "-I":
		req.Head = true
		req.Method = "HEAD"
		return nil
	case arg == "-o":
		v, err := nextValue(arg)
		req.Output = v
		return err
	case strings.HasPrefix(arg, "-o") && len(arg) > 2:
		req.Output = arg[2:]
		return nil
	case arg == "-i":
		req.IncludeHeaders = true
		return nil
	case arg == "-s":
		req.Silent = true
		return nil
	case arg == "-v":
		req.UnsupportedArgs = append(req.UnsupportedArgs, arg)
		return nil
	default:
		if strings.HasPrefix(arg, "-") {
			req.UnsupportedArgs = append(req.UnsupportedArgs, arg)
		}
		return nil
	}
}

func (r *curlRequest) addHeader(header string) {
	r.Headers = append(r.Headers, header)
	name := strings.ToLower(strings.TrimSpace(strings.SplitN(header, ":", 2)[0]))
	r.UserHeaderNames[name] = true
	switch name {
	case "x-akamai-acs-action":
		r.ActionHeaderSeen = true
	case "x-akamai-acs-auth-data":
		r.AuthDataSeen = true
	case "x-akamai-acs-auth-sign":
		r.AuthSignSeen = true
	}
}

func splitLongOpt(arg string) (name, value string, hasInline bool) {
	if before, after, ok := strings.Cut(arg, "="); ok {
		return before, after, true
	}
	return arg, "", false
}

func looksLikeURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func resolveCredentials(acs acsOptions, env map[string]string) (credentials, error) {
	configPath := acs.ConfigPath
	if !acs.ConfigPathSet {
		configPath = firstNonEmpty(env["NETSTORAGE_CONFIG"], acs.ConfigPath)
	}
	section := acs.Section
	if !acs.SectionSet {
		section = firstNonEmpty(env["NETSTORAGE_SECTION"], acs.Section)
	}
	cfg, err := readConfig(configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return credentials{}, err
	}
	account := firstNonEmpty(acs.Account, env["NETSTORAGE_ACCOUNT"], cfg[section]["account"])
	key := firstNonEmpty(acs.Key, env["NETSTORAGE_KEY"], cfg[section]["key"])
	return credentials{Account: account, Key: key}, nil
}

func readConfig(path string) (map[string]map[string]string, error) {
	expanded, err := expandPath(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(expanded)
	if err != nil {
		return map[string]map[string]string{}, err
	}
	defer f.Close()

	result := map[string]map[string]string{}
	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if result[section] == nil {
				result[section] = map[string]string{}
			}
			continue
		}
		if section == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		result[section][strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return result, scanner.Err()
}

func expandPath(path string) (string, error) {
	if path == "~" {
		return os.UserHomeDir()
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func validateRequest(acs acsOptions, req curlRequest, creds credentials) error {
	if req.URL == "" {
		return errors.New("URL is required")
	}
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path == "" || !strings.HasPrefix(u.Path, "/") {
		return fmt.Errorf("invalid URL: %s", req.URL)
	}
	if acs.Action == "" {
		return errors.New("--acs-action is required")
	}
	values, err := url.ParseQuery(acs.Action)
	if err != nil || values.Get("version") != "1" {
		return errors.New("--acs-action must contain version=1")
	}
	if creds.Account == "" {
		return errors.New("account is required; use --acs-account, NETSTORAGE_ACCOUNT, or ~/.nsuacsrc")
	}
	if creds.Key == "" {
		return errors.New("key is required; use --acs-key, NETSTORAGE_KEY, or ~/.nsuacsrc")
	}
	if req.AuthDataSeen || req.AuthSignSeen {
		return errors.New("do not specify X-Akamai-ACS-Auth-Data or X-Akamai-ACS-Auth-Sign manually")
	}
	if req.ActionHeaderSeen {
		return errors.New("do not specify X-Akamai-ACS-Action with -H; use --acs-action")
	}
	if acs.SignVersion != 3 && acs.SignVersion != 4 && acs.SignVersion != 5 {
		return errors.New("--acs-sign-version must be 3, 4, or 5")
	}
	return nil
}

func newUniqueID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func signRequest(in signerInput) (signedHeaders, error) {
	u, err := url.Parse(in.URL)
	if err != nil {
		return signedHeaders{}, err
	}
	requestPath := u.EscapedPath()
	if requestPath == "" {
		requestPath = "/"
	}
	if u.RawQuery != "" {
		requestPath += "?" + u.RawQuery
	}
	authData := fmt.Sprintf("%d, 0.0.0.0, 0.0.0.0, %d, %s, %s",
		in.SignVersion, in.Now.Unix(), in.UniqueID, in.Account)
	signString := requestPath + "\n" + "x-akamai-acs-action:" + strings.TrimSpace(in.Action) + "\n"
	mac, err := hmacForVersion(in.SignVersion, []byte(in.Key))
	if err != nil {
		return signedHeaders{}, err
	}
	mac.Write([]byte(authData + signString))
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return signedHeaders{
		Action:   in.Action,
		AuthData: authData,
		AuthSign: sign,
	}, nil
}

func hmacForVersion(version int, key []byte) (hash.Hash, error) {
	switch version {
	case 3:
		return hmac.New(md5.New, key), nil
	case 4:
		return hmac.New(sha1.New, key), nil
	case 5:
		return hmac.New(sha256.New, key), nil
	default:
		return nil, errors.New("unsupported signature version")
	}
}

func runCurl(curlPath string, req curlRequest, headers signedHeaders, stdout, stderr io.Writer) (int, error) {
	args := buildCurlArgs(req, headers)
	cmd := exec.Command(curlPath, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}

func buildCurlArgs(req curlRequest, headers signedHeaders) []string {
	added := []string{
		"-H", "X-Akamai-ACS-Action: " + headers.Action,
		"-H", "X-Akamai-ACS-Auth-Data: " + headers.AuthData,
		"-H", "X-Akamai-ACS-Auth-Sign: " + headers.AuthSign,
	}
	out := make([]string, 0, len(req.Args)+len(added))
	insertAt := -1
	for i, arg := range req.Args {
		if looksLikeURL(arg) {
			insertAt = i
		}
	}
	for i, arg := range req.Args {
		if i == insertAt {
			out = append(out, added...)
		}
		out = append(out, arg)
	}
	if insertAt < 0 {
		out = append(out, added...)
	}
	return out
}

func runHTTP(req curlRequest, headers signedHeaders, stdout, stderr io.Writer) (int, error) {
	if len(req.UnsupportedArgs) > 0 {
		return 2, fmt.Errorf("curl is not installed and these curl options are not supported by the net/http fallback: %s", strings.Join(req.UnsupportedArgs, ", "))
	}
	body, err := requestBody(req.Data)
	if err != nil {
		return 1, err
	}
	httpReq, err := http.NewRequest(req.Method, req.URL, body)
	if err != nil {
		return 2, err
	}
	for _, h := range req.Headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return 2, fmt.Errorf("invalid header: %s", h)
		}
		httpReq.Header.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	httpReq.Header.Set("X-Akamai-ACS-Action", headers.Action)
	httpReq.Header.Set("X-Akamai-ACS-Auth-Data", headers.AuthData)
	httpReq.Header.Set("X-Akamai-ACS-Auth-Sign", headers.AuthSign)

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return 1, err
	}
	defer resp.Body.Close()

	var bodyOut io.Writer = stdout
	var file *os.File
	if req.Output != "" {
		file, err = os.Create(req.Output)
		if err != nil {
			return 1, err
		}
		defer file.Close()
		bodyOut = file
	}
	if req.IncludeHeaders {
		writeResponseHeaders(stdout, resp)
	}
	if req.Method != "HEAD" {
		if _, err := io.Copy(bodyOut, resp.Body); err != nil {
			return 1, err
		}
	}
	_ = stderr
	return 0, nil
}

func requestBody(data *dataSpec) (io.Reader, error) {
	if data == nil {
		return nil, nil
	}
	if strings.HasPrefix(data.Value, "@") {
		b, err := os.ReadFile(data.Value[1:])
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(b), nil
	}
	return strings.NewReader(data.Value), nil
}

func writeResponseHeaders(w io.Writer, resp *http.Response) {
	fmt.Fprintf(w, "HTTP/%d.%d %03d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, http.StatusText(resp.StatusCode))
	for k, values := range resp.Header {
		for _, v := range values {
			fmt.Fprintf(w, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprint(w, "\r\n")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func envMap(environ []string) map[string]string {
	m := map[string]string{}
	for _, item := range environ {
		k, v, ok := strings.Cut(item, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  nsucurl [--acs-account ACCOUNT] [--acs-key KEY] --acs-action ACTION [curl-options] URL

NetStorage authentication options:
  --acs-config FILE          credential file path (default: ~/.nsuacsrc)
  --acs-section SECTION      credential section (default: default)
  --acs-account ACCOUNT      NetStorage upload account ID
  --acs-key KEY              NetStorage HTTP API key
  --acs-action ACTION        X-Akamai-ACS-Action value, including version=1
  --acs-sign-version 3|4|5   signature version (default: 5)

Example:
  nsucurl --acs-action 'version=1&action=stat' \
    https://example-nsu.akamaihd.net/123456/path/file.txt
`)
}
