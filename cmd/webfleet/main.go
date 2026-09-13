package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"github.com/webfleet-cv/webfleet/internal/config"
	"github.com/webfleet-cv/webfleet/internal/crawler"
	"github.com/webfleet-cv/webfleet/internal/dnsobs"
	"github.com/webfleet-cv/webfleet/internal/monitor"
	"github.com/webfleet-cv/webfleet/internal/notifications"
	"github.com/webfleet-cv/webfleet/internal/scheduler"
	"github.com/webfleet-cv/webfleet/internal/server"
	"github.com/webfleet-cv/webfleet/internal/service"
	"github.com/webfleet-cv/webfleet/internal/store"
	"github.com/webfleet-cv/webfleet/internal/tlshealth"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// version is overridden at release build time via -ldflags -X main.version.
var version = "0.1.1"

func main() {
	// Service-management commands must remain usable even when the application
	// configuration is unhealthy, so dispatch before any runtime config load.
	if len(os.Args) >= 2 && os.Args[1] == "service" {
		os.Exit(runService(os.Args[2:]))
	}
	if len(os.Args) >= 2 && os.Args[1] == "reset" {
		os.Exit(runReset(os.Args[2:]))
	}
	if len(os.Args) >= 2 && os.Args[1] == "config" {
		os.Exit(runConfig(os.Args[2:]))
	}
	if len(os.Args) >= 2 && os.Args[1] == "setup" {
		os.Exit(runSetup(os.Args[2:]))
	}
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Fprintln(os.Stdout, version)
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		log.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	log.Info("webfleet version", "version", version)
	if len(os.Args) >= 3 && os.Args[1] == "backup" {
		provider := store.Provider(cfg.DatabaseURL)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if provider == "postgres" {
			if err := store.PostgresBackup(ctx, cfg.DatabaseURL, os.Args[2]); err != nil {
				log.Error("postgres backup failed", "error", err)
				os.Exit(1)
			}
		} else {
			st, err := store.Open(cfg.DataDir)
			if err != nil {
				log.Error("database failed", "error", err)
				os.Exit(1)
			}
			defer st.Close()
			if err := st.Backup(os.Args[2]); err != nil {
				log.Error("backup failed", "error", err)
				os.Exit(1)
			}
		}
		log.Info("backup complete", "provider", provider, "path", os.Args[2])
		return
	}
	if len(os.Args) >= 3 && os.Args[1] == "restore" {
		provider := store.Provider(cfg.DatabaseURL)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if provider == "postgres" {
			if err := store.PostgresRestore(ctx, cfg.DatabaseURL, os.Args[2]); err != nil {
				log.Error("postgres restore failed", "error", err)
				os.Exit(1)
			}
		} else {
			if err := store.Restore(cfg.DataDir, os.Args[2]); err != nil {
				log.Error("restore failed", "error", err)
				os.Exit(1)
			}
		}
		log.Info("restore complete", "provider", provider, "source", os.Args[2])
		return
	}
	// Foreground server: strip the mode word (serve/worker/analytics-ingest) so
	// `webfleet serve --host ...` and the recorded unit form `webfleet --host
	// ... --port ...` both parse identically, then resolve the shared
	// --host/--port listener flags.
	args := os.Args[1:]
	mode := "integrated"
	if len(args) > 0 {
		switch args[0] {
		case "serve", "worker", "analytics-ingest":
			mode = args[0]
			args = args[1:]
		default:
			if !strings.HasPrefix(args[0], "-") {
				fmt.Fprintln(os.Stderr, "webfleet: unknown command", args[0])
				os.Exit(2)
			}
		}
	}
	fs := flag.NewFlagSet("webfleet", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host := fs.String("host", "", "HTTP bind host (default 127.0.0.1; WEBFLEET_HOST overrides, CLI wins)")
	port := fs.String("port", "", "HTTP bind port, 1-65535 (default 7336; WEBFLEET_PORT overrides, CLI wins)")
	if err := fs.Parse(args); err != nil {
		log.Error("arguments", "error", err)
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		log.Error("arguments", "error", fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " ")))
		os.Exit(2)
	}
	addr, err := resolveListener(*host, *port, "", flagProvided(fs, "host"), flagProvided(fs, "port"), false)
	if err != nil {
		log.Error("listener", "error", err)
		os.Exit(2)
	}
	// An explicitly selected --host/--port (CLI or WEBFLEET_HOST/WEBFLEET_PORT)
	// overrides the listener loaded by config.Load (WEBFLEET_LISTEN or the
	// default) in memory, so the advertised override genuinely controls the
	// runtime bind. A bare invocation or the legacy WEBFLEET_LISTEN keeps the
	// loaded listener; no durable file is written or rewritten.
	if listenerOverrideSelected(fs) {
		cfg.Listen = addr
	}
	var st *store.Store
	if cfg.DatabaseURL != "" {
		st, err = store.OpenPostgres(context.Background(), cfg.DatabaseURL)
	} else {
		st, err = store.Open(cfg.DataDir)
	}
	if err != nil {
		log.Error("database failed", "error", err)
		os.Exit(1)
	}
	defer st.Close()
	mon := monitor.New(st)
	tlsSvc := tlshealth.New(st)
	dnsSvc := dnsobs.New(st)
	crawlSvc := crawler.New(st)
	var sched *scheduler.Scheduler
	if mode == "integrated" || mode == "worker" {
		sched = scheduler.New(st, mon, tlsSvc, dnsSvc, crawlSvc, cfg.CheckInterval, cfg.CrawlInterval, cfg.CheckConcurrency, log)
		sched.Start(context.Background())
		defer sched.Stop()
		// Webhook outbox delivery runs wherever background work runs, so a
		// slow webhook can never block an incident transition.
		nw := notifications.NewWorker(st, log)
		nw.Start(context.Background())
		defer nw.Stop()
	}
	if mode == "worker" {
		log.Info("webfleet worker started")
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		return
	}
	var srv *server.Server
	if mode == "analytics-ingest" {
		srv = server.NewAnalyticsIngest(cfg, st, log)
	} else {
		srv = server.New(cfg, st, log)
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("webfleet starting", "listen", cfg.Listen, "data", cfg.DataDir, "mode", mode)
		errc <- srv.ListenAndServe()
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
		log.Info("shutdown requested")
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server failed", "error", fmt.Errorf("%v (listener: %s)", err, cfg.Listen))
			os.Exit(1)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("shutdown failed", "error", err)
	}
}

// listenerOverrideSelected reports whether the user explicitly selected the
// new host/port listener form (CLI flags or WEBFLEET_HOST/WEBFLEET_PORT
// environment). The legacy WEBFLEET_LISTEN and bare invocations keep the
// listener loaded by config.Load.
func listenerOverrideSelected(fs *flag.FlagSet) bool {
	if flagProvided(fs, "host") || flagProvided(fs, "port") {
		return true
	}
	if _, ok := os.LookupEnv("WEBFLEET_HOST"); ok {
		return true
	}
	if _, ok := os.LookupEnv("WEBFLEET_PORT"); ok {
		return true
	}
	return false
}

// listenerSelectionActive reports whether the user supplied any explicit
// listener selection, through CLI flags or the WEBFLEET_HOST/WEBFLEET_PORT/
// WEBFLEET_LISTEN environment variables. A bare invocation with none of these
// is the reinstall-preservation path.
func listenerSelectionActive(hostSet, portSet, listenSet bool) bool {
	if hostSet || portSet || listenSet {
		return true
	}
	if _, ok := os.LookupEnv("WEBFLEET_HOST"); ok {
		return true
	}
	if _, ok := os.LookupEnv("WEBFLEET_PORT"); ok {
		return true
	}
	if _, ok := os.LookupEnv("WEBFLEET_LISTEN"); ok {
		return true
	}
	return false
}

// serviceCommand is the fully parsed `webfleet service <verb>` invocation.
type serviceCommand struct {
	verb     string
	data     string
	listen   string
	host     string
	port     string
	follow   bool
	artifact string
	sha      string
}

// serviceSuccessMessage returns the state-neutral success message for a
// completed service command. The lifecycle deliberately preserves prior state
// (a stopped service stays stopped across reinstall/update/rollback), so
// install/update/rollback must not claim the service is active or was
// restarted; only the verbs whose effect is inherently a state change
// (start/stop/restart/enable/disable) state it.
func serviceSuccessMessage(c serviceCommand) string {
	switch c.verb {
	case "install":
		return "webfleet.service installed."
	case "uninstall":
		return "webfleet.service uninstalled. Persistent data was preserved."
	case "start":
		return "webfleet.service started."
	case "stop":
		return "webfleet.service stopped."
	case "restart":
		return "webfleet.service restarted."
	case "enable":
		return "webfleet.service enabled at boot."
	case "disable":
		return "webfleet.service disabled at boot."
	case "update":
		return "webfleet.service updated."
	case "rollback":
		return "webfleet.service rolled back."
	default:
		return ""
	}
}

// execServiceCommand dispatches a parsed service command to the lifecycle,
// returning the success message (or status/logs body) to print. It is a
// variable so the CLI can be tested end-to-end without root or systemd.
var execServiceCommand = func(c serviceCommand) (string, error) {
	switch c.verb {
	case "install":
		// A legacy --listen bootstrap records the single address; the explicit
		// --host/--port form records the canonical pair in ExecStart so the
		// runtime listener survives restart/reboot.
		if c.listen != "" {
			if err := service.Install(service.Executable(), c.data, c.listen); err != nil {
				return "", err
			}
		} else {
			if err := service.InstallExplicit(service.Executable(), c.data, c.host, c.port); err != nil {
				return "", err
			}
		}
	case "uninstall":
		if err := service.Uninstall(); err != nil {
			return "", err
		}
	case "start":
		if err := service.Start(); err != nil {
			return "", err
		}
	case "stop":
		if err := service.Stop(); err != nil {
			return "", err
		}
	case "restart":
		if err := service.Restart(); err != nil {
			return "", err
		}
	case "enable":
		if err := service.Enable(); err != nil {
			return "", err
		}
	case "disable":
		if err := service.Disable(); err != nil {
			return "", err
		}
	case "status":
		var b bytes.Buffer
		if err := service.Status(&b); err != nil {
			return b.String(), err
		}
		return b.String(), nil
	case "logs":
		var b bytes.Buffer
		if err := service.Logs(c.follow, &b); err != nil {
			return b.String(), err
		}
		return b.String(), nil
	case "update":
		if err := service.Update(c.artifact, c.sha); err != nil {
			return "", err
		}
	case "rollback":
		if err := service.Rollback(); err != nil {
			return "", err
		}
	}
	return serviceSuccessMessage(c), nil
}

// parseServiceCommand deterministically parses `webfleet service <verb>` with
// command-local flags, preserving `--flag value` pairs that the previous
// separator-based parser could not (it stripped flag values into positionals).
// Exit-code model: 0 success, 1 operational failure, 2 usage error.
func parseServiceCommand(args []string) (serviceCommand, error) {
	if len(args) == 0 {
		args = []string{"status"}
	}
	verb := args[0]
	rest := args[1:]
	cmd := serviceCommand{verb: verb}
	switch verb {
	case "install":
		fs := flag.NewFlagSet("install", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		data := fs.String("data", "", "data directory")
		dataDir := fs.String("data-dir", "", "data directory")
		listen := fs.String("listen", "", "listen address (legacy; alternative to --host/--port, honors WEBFLEET_LISTEN)")
		host := fs.String("host", "", "HTTP bind host (default 127.0.0.1; WEBFLEET_HOST overrides, CLI wins)")
		port := fs.String("port", "", "HTTP bind port, 1-65535 (default 7336; WEBFLEET_PORT overrides, CLI wins)")
		if err := fs.Parse(rest); err != nil {
			return cmd, fmt.Errorf("install: %v", err)
		}
		if fs.NArg() != 0 {
			return cmd, fmt.Errorf("install takes no positional arguments: %s", strings.Join(fs.Args(), " "))
		}
		if flagProvided(fs, "data") && flagProvided(fs, "data-dir") {
			return cmd, fmt.Errorf("install: --data and --data-dir cannot be combined")
		}
		cmd.data = *data
		if *dataDir != "" {
			cmd.data = *dataDir
		}
		if cmd.data == "" {
			cmd.data = service.DefaultDataDir
		}
		// Only install resolves and validates the listener environment
		// (WEBFLEET_HOST/WEBFLEET_PORT/WEBFLEET_LISTEN), so malformed listener
		// env in the invoking shell never breaks the other service verbs.
		addr, legacy, err := resolveServiceInstall(*host, *port, *listen, flagProvided(fs, "host"), flagProvided(fs, "port"), flagProvided(fs, "listen"))
		if err != nil {
			return cmd, fmt.Errorf("install: %v", err)
		}
		// A bare reinstall with no explicit listener selection preserves an
		// existing valid managed unit's recorded listener and form, so rerunning
		// `webfleet service install` never silently changes a custom or legacy
		// installation. A foreign/malformed/modified existing unit fails closed.
		if !listenerSelectionActive(flagProvided(fs, "host"), flagProvided(fs, "port"), flagProvided(fs, "listen")) {
			existingListen, existingExplicit, exists, ierr := service.InstalledListener()
			if ierr != nil {
				return cmd, fmt.Errorf("install: existing unit is not valid: %v", ierr)
			}
			if exists {
				if existingExplicit {
					cmd.host, cmd.port, ierr = net.SplitHostPort(existingListen)
					if ierr != nil {
						return cmd, fmt.Errorf("install: existing unit has an invalid recorded listener %q: %v", existingListen, ierr)
					}
					return cmd, nil
				}
				cmd.listen = existingListen
				return cmd, nil
			}
		}
		if legacy {
			cmd.listen = addr
			return cmd, nil
		}
		cmd.host, cmd.port, err = net.SplitHostPort(addr)
		if err != nil {
			return cmd, fmt.Errorf("install: cannot split resolved listener %q: %v", addr, err)
		}
		return cmd, nil
	case "logs":
		fs := flag.NewFlagSet("logs", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		follow := fs.Bool("follow", false, "tail live journal output")
		if err := fs.Parse(rest); err != nil {
			return cmd, fmt.Errorf("logs: %v", err)
		}
		if fs.NArg() != 0 {
			return cmd, fmt.Errorf("logs takes no positional arguments: %s", strings.Join(fs.Args(), " "))
		}
		cmd.follow = *follow
		return cmd, nil
	case "update":
		for _, a := range rest {
			if strings.HasPrefix(a, "-") {
				return cmd, fmt.Errorf("update takes no flags: %s", a)
			}
		}
		if len(rest) != 2 {
			return cmd, fmt.Errorf("usage: webfleet service update ARTIFACT SHA256")
		}
		cmd.artifact = rest[0]
		cmd.sha = rest[1]
		return cmd, nil
	case "uninstall", "start", "stop", "restart", "enable", "disable", "status", "rollback":
		for _, a := range rest {
			if strings.HasPrefix(a, "-") {
				return cmd, fmt.Errorf("%s takes no flags: %s", verb, a)
			}
		}
		if len(rest) != 0 {
			return cmd, fmt.Errorf("%s takes no positional arguments: %s", verb, strings.Join(rest, " "))
		}
		return cmd, nil
	default:
		return cmd, fmt.Errorf("unknown service command %q\n\nUsage: webfleet service <install|uninstall|start|stop|restart|status|enable|disable|logs|update|rollback> [flags]", verb)
	}
}

// resolveServiceInstall resolves the listener recorded by `webfleet service
// install` and reports whether the recorded form is the legacy bootstrap
// single address (--listen / WEBFLEET_LISTEN) or the explicit --host/--port
// pair. Precedence and conflict rules are identical to the foreground:
// CLI > env > default, --listen conflicts with --host/--port, and env-only
// WEBFLEET_LISTEN + WEBFLEET_HOST/WEBFLEET_PORT conflicts fail clearly.
func resolveServiceInstall(hostFlag, portFlag, listenFlag string, hostSet, portSet, listenSet bool) (string, bool, error) {
	addr, err := resolveListener(hostFlag, portFlag, listenFlag, hostSet, portSet, listenSet)
	if err != nil {
		return "", false, err
	}
	legacy := listenSet
	if !legacy {
		if _, hasListen := os.LookupEnv("WEBFLEET_LISTEN"); hasListen && !hostSet && !portSet {
			legacy = true
		}
	}
	return addr, legacy, nil
}

// runServiceIO runs a parsed `webfleet service` command against the lifecycle
// seam and writes diagnostics to the supplied writers. It is the testable core
// of runService.
func runServiceIO(out, errOut io.Writer, args []string) int {
	cmd, err := parseServiceCommand(args)
	if err != nil {
		fmt.Fprintf(errOut, "webfleet service: %v\n", err)
		return 2
	}
	output, err := execServiceCommand(cmd)
	if err != nil {
		fmt.Fprintf(errOut, "webfleet service %s: %v\n", cmd.verb, err)
		return 1
	}
	if output != "" {
		fmt.Fprintln(out, output)
	}
	return 0
}

// runService dispatches `webfleet service <command>` with the same CLI shape,
// exit-code model and diagnostics as the sibling projects (Cortex, Warden,
// Trestle, Watchpost), while operating the Web Fleet systemd **system** unit.
func runService(args []string) int {
	return runServiceIO(os.Stdout, os.Stderr, args)
}
