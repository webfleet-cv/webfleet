package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type replicateAuth struct {
	cookie *http.Cookie
	csrf   string
}

func runReplicate(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: webfleet replicate <status|join|snapshot>")
		return 2
	}
	command := args[0]
	fs := flag.NewFlagSet("webfleet replicate "+command, flag.ContinueOnError)
	url := fs.String("url", "http://127.0.0.1:7336", "Webfleet base URL")
	user := fs.String("user", os.Getenv("WEBFLEET_ADMIN_USER"), "administrator username/email")
	pass := fs.String("password", os.Getenv("WEBFLEET_ADMIN_PASSWORD"), "administrator password")
	if fs.Parse(args[1:]) != nil {
		return 2
	}
	if *user == "" || *pass == "" {
		fmt.Fprintln(os.Stderr, "replicate: --user and --password (or WEBFLEET_ADMIN_USER/WEBFLEET_ADMIN_PASSWORD) are required")
		return 2
	}
	client := &http.Client{}
	auth, err := replicateLogin(client, *url, *user, *pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "replicate:", err)
		return 1
	}
	var method, path string
	var payload any
	switch command {
	case "status":
		method, path = http.MethodGet, "/api/cluster/v1/replication/status"
		if fs.NArg() != 0 {
			return 2
		}
	case "snapshot":
		method, path = http.MethodPost, "/api/cluster/v1/replication/snapshot"
		if fs.NArg() != 0 {
			return 2
		}
	case "join":
		if fs.NArg() != 2 {
			fmt.Fprintln(os.Stderr, "usage: webfleet replicate join [flags] <node-id> <raft-address>")
			return 2
		}
		method, path = http.MethodPost, "/api/cluster/v1/replication/join"
		payload = map[string]string{"node_id": fs.Arg(0), "address": fs.Arg(1)}
	default:
		fmt.Fprintln(os.Stderr, "replicate: unknown command", command)
		return 2
	}
	body, err := replicateCall(client, *url, method, path, payload, auth)
	if err != nil {
		fmt.Fprintln(os.Stderr, "replicate:", err)
		return 1
	}
	if len(bytes.TrimSpace(body)) != 0 {
		fmt.Println(string(bytes.TrimSpace(body)))
	}
	return 0
}

func replicateLogin(client *http.Client, base, user, pass string) (*replicateAuth, error) {
	b, _ := json.Marshal(map[string]string{"email": user, "password": pass})
	req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/")+"/api/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed: %s", strings.TrimSpace(string(body)))
	}
	var session struct {
		CSRF string `json:"csrf"`
	}
	if json.Unmarshal(body, &session) != nil || session.CSRF == "" {
		return nil, errors.New("login response missing CSRF token")
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "webfleet_session" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		return nil, errors.New("login response missing session cookie")
	}
	return &replicateAuth{cookie: cookie, csrf: session.CSRF}, nil
}

func replicateCall(client *http.Client, base, method, path string, payload any, a *replicateAuth) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, strings.TrimRight(base, "/")+path, body)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(a.cookie)
	if method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}
