package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/webfleet-cv/webfleet/internal/auth"
	"github.com/webfleet-cv/webfleet/internal/config"
	"github.com/webfleet-cv/webfleet/internal/service"
	"github.com/webfleet-cv/webfleet/internal/store"
)

// withInstalledDataDir applies the canonical instance-resolution precedence
// shared by setup/config/reset: WEBFLEET_DATA_DIR wins, then the data directory
// recorded by the installed managed service, then the normal default. The
// installed directory is injected through the environment because config.Load
// already honors WEBFLEET_DATA_DIR; the returned cleanup restores the
// environment. It fails closed rather than silently targeting a different
// instance when the installed unit exists but cannot be used safely.
func withInstalledDataDir() (func(), error) {
	if strings.TrimSpace(os.Getenv("WEBFLEET_DATA_DIR")) != "" {
		return func() {}, nil
	}
	installedData, installed, installedErr := service.InstalledDataDir()
	if installedErr != nil {
		return nil, installedErr
	}
	if !installed {
		return func() {}, nil
	}
	_ = os.Setenv("WEBFLEET_DATA_DIR", installedData)
	return func() { _ = os.Unsetenv("WEBFLEET_DATA_DIR") }, nil
}

func runSetup(args []string) int {
	fs := flag.NewFlagSet("webfleet setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	email := fs.String("email", "", "administrator email")
	emailFile := fs.String("email-file", "", "file containing administrator email")
	username := fs.String("username", "", "administrator username")
	passwordFile := fs.String("password-file", "", "file containing password")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *passwordFile == "" {
		fmt.Fprintln(os.Stderr, "usage: webfleet setup (--email ADDRESS|--email-file FILE) --username NAME --password-file FILE")
		return 2
	}
	if *emailFile != "" {
		raw, err := os.ReadFile(*emailFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "webfleet:", err)
			return 1
		}
		*email = strings.TrimSpace(string(raw))
	}
	if *email == "" {
		fmt.Fprintln(os.Stderr, "webfleet: --email or --email-file is required")
		return 2
	}
	password, err := os.ReadFile(*passwordFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "webfleet:", err)
		return 1
	}
	cleanup, err := withInstalledDataDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "webfleet:", err)
		return 1
	}
	defer cleanup()
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "webfleet:", err)
		return 1
	}
	var db *store.Store
	if cfg.DatabaseURL != "" {
		db, err = store.OpenPostgres(context.Background(), cfg.DatabaseURL)
	} else {
		db, err = store.Open(cfg.DataDir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "webfleet:", err)
		return 1
	}
	defer db.Close()
	if err = auth.New(db).CreateAdmin(*username, *email, strings.TrimRight(string(password), "\r\n")); err != nil {
		fmt.Fprintln(os.Stderr, "webfleet:", err)
		return 1
	}
	fmt.Println("Webfleet administrator configured.")
	return 0
}

func runConfig(args []string) int {
	fs := flag.NewFlagSet("webfleet config", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || fs.Arg(0) != "show" {
		fmt.Fprintln(os.Stderr, "usage: webfleet config show [--json]")
		return 2
	}
	cleanup, err := withInstalledDataDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "webfleet:", err)
		return 1
	}
	defer cleanup()
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "webfleet:", err)
		return 1
	}
	value := map[string]any{"project": "webfleet", "dataDir": cfg.DataDir, "databaseProvider": store.Provider(cfg.DatabaseURL), "listen": cfg.Listen}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(value)
	} else {
		fmt.Printf("Data directory: %s\nDatabase: %s\nListen: %s\n", cfg.DataDir, store.Provider(cfg.DatabaseURL), cfg.Listen)
	}
	return 0
}

func runReset(args []string) int {
	fs := flag.NewFlagSet("webfleet reset", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	auth := fs.Bool("auth", false, "reset accounts and sessions only")
	all := fs.Bool("all", false, "reset all Webfleet state")
	confirm := fs.String("confirm", "", "non-interactive confirmation")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*auth == *all) {
		fmt.Fprintln(os.Stderr, "usage: webfleet reset (--auth|--all) [--confirm 'WEBFLEET AUTH|WEBFLEET ALL']")
		return 2
	}
	cleanup, err := withInstalledDataDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "webfleet:", err)
		return 1
	}
	defer cleanup()
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "webfleet:", err)
		return 1
	}
	mode := "AUTH"
	if *all {
		mode = "ALL"
	}
	want := "WEBFLEET " + mode
	if !confirmWebfleet(want, *confirm) {
		fmt.Fprintln(os.Stderr, "webfleet: confirmation did not match; nothing changed")
		return 1
	}
	if cfg.DatabaseURL != "" {
		fmt.Fprintln(os.Stderr, "webfleet: reset currently requires the SQLite provider; use a database-native backup/reset workflow for PostgreSQL")
		return 1
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if *all {
		if _, err = os.Stat(cfg.DataDir); os.IsNotExist(err) {
			return 0
		}
		info, statErr := os.Stat(cfg.DataDir)
		if statErr != nil {
			return 1
		}
		if err = os.Rename(cfg.DataDir, cfg.DataDir+".reset-"+stamp); err != nil {
			fmt.Fprintln(os.Stderr, "webfleet: back up data directory:", err)
			return 1
		}
		if err = os.MkdirAll(cfg.DataDir, 0700); err != nil {
			fmt.Fprintln(os.Stderr, "webfleet:", err)
			return 1
		}
		// The installed service runs as the dedicated service user. Preserve
		// the original owner on the recreated directory (the pre-reset state
		// was writable by the service), otherwise the service cannot open or
		// secure its database after reset --all.
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			if err = os.Chown(cfg.DataDir, int(stat.Uid), int(stat.Gid)); err != nil {
				fmt.Fprintln(os.Stderr, "webfleet: preserve data directory ownership:", err)
				return 1
			}
		}
	} else {
		db, openErr := store.Open(cfg.DataDir)
		if openErr != nil {
			fmt.Fprintln(os.Stderr, "webfleet:", openErr)
			return 1
		}
		defer db.Close()
		backupPath := cfg.DataDir + "/reset-auth-" + stamp + ".db"
		if err = db.Backup(backupPath); err != nil {
			fmt.Fprintln(os.Stderr, "webfleet: back up database:", err)
			return 1
		}
		tx, beginErr := db.DB.BeginTx(context.Background(), nil)
		if beginErr != nil {
			fmt.Fprintln(os.Stderr, "webfleet:", beginErr)
			return 1
		}
		defer tx.Rollback()
		for _, q := range []string{"DELETE FROM sessions", "DELETE FROM users"} {
			if _, err = tx.Exec(q); err != nil {
				fmt.Fprintln(os.Stderr, "webfleet:", err)
				return 1
			}
		}
		if err = tx.Commit(); err != nil {
			fmt.Fprintln(os.Stderr, "webfleet:", err)
			return 1
		}
	}
	fmt.Printf("Webfleet %s reset complete. A timestamped backup was retained.\n", strings.ToLower(mode))
	return 0
}

func confirmWebfleet(want, supplied string) bool {
	if supplied != "" {
		return supplied == want
	}
	fmt.Fprintf(os.Stderr, "Type %q to continue: ", want)
	got, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(got) == want
}
