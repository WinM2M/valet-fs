// valetd is the ValetFS desktop daemon.
//
// In --dev mode it skips WebRTC signaling and exposes a local HTTP control
// API for end-to-end testing of the VFS mount/sync/unmount lifecycle.
// In production mode it bootstraps a WebRTC session through a Cloudflare
// Worker and prints an ASCII QR code for the mobile app to scan.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/anomalyco/valet-fs/internal/config"
	"github.com/anomalyco/valet-fs/internal/daemon"
	"github.com/anomalyco/valet-fs/internal/vfs"
	"github.com/anomalyco/valet-fs/internal/webrtc"
)

type runtimeState struct {
	ControlAddr  string `json:"control_addr"`
	ControlToken string `json:"control_token"`
}

var cliVerbose bool

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			serve(os.Args[2:])
			return
		case "stop", "status", "ls", "cat", "cp", "rm", "del", "mkdir", "rmdir", "mv", "completion", "__complete":
			if err := runCLI(os.Args[1:]); err != nil {
				_, _ = fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			return
		}
	}
	_, _ = fmt.Fprintln(os.Stderr, "usage: valetfs serve [options] | valetfs <command>")
	os.Exit(1)
}

func serve(args []string) {
	cfg, err := config.Load(args)
	if err != nil {
		log.Fatalf("valetfs: config error: %v", err)
	}
	if cfg.RecordRuntimeState {
		if running, _ := detectExistingDaemon(cfg.RuntimeDir); running {
			_, _ = fmt.Fprintln(os.Stderr, "Daemon is already running. Use `valetfs stop` to stop the existing daemon.")
			os.Exit(1)
		}
	}

	// Phase 3 rule 1: idempotent ghost-unmount before we touch the mountpoint.
	vfs.PreUnmount(cfg.MountPoint)

	d, err := daemon.New(cfg)
	if err != nil {
		log.Fatalf("valetd: init error: %v", err)
	}

	// Phase 3 rule 2: install signal trap before any sensitive state exists.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	if err := d.StartDevAPI(); err != nil {
		log.Fatalf("valetd: control api: %v", err)
	}
	if err := d.Mount(); err != nil {
		log.Fatalf("valetd: mount: %v", err)
	}

	if cfg.Dev {
		log.Println("valetd: starting in DEV mode (no WebRTC)")
	} else {
		log.Println("valetd: starting in PRODUCTION mode")
		peer, err := webrtc.New()
		if err != nil {
			log.Fatalf("valetd: webrtc: %v", err)
		}
		peer.OnOpen(func() {
			log.Println("valetd: data channel open; mounting VFS")
			if err := d.Mount(); err != nil {
				log.Printf("valetd: mount error after pairing: %v", err)
			}
		})
		peer.OnData(func(msg []byte) {
			// In a full implementation the mobile app posts file ops here.
			log.Printf("valetd: data channel rx: %d bytes", len(msg))
		})
		go func() {
			if err := peer.Bootstrap(cfg.SignalingURL); err != nil {
				log.Printf("valetd: bootstrap error: %v", err)
			}
		}()
		defer peer.Close()
	}

	// Block until a termination signal arrives.
	sig := <-sigCh
	log.Printf("valetd: received signal %s; shutting down", sig)

	// Phase 3 rule 3: Graceful Shutdown wipes heap and unmounts.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.Shutdown(ctx); err != nil {
		log.Printf("valetd: shutdown error: %v", err)
	}
	log.Println("valetfs: bye")
}

func runCLI(args []string) error {
	verbose, daemonAddr, cmdArgs := parseGlobalCLIOptions(args)
	cliVerbose = verbose
	args = cmdArgs
	if len(args) == 0 {
		return fmt.Errorf("missing command")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	st, err := loadRuntimeState(filepath.Join(home, ".valetfs", "run", "runtime.json"))
	if err != nil {
		return err
	}
	if daemonAddr != "" {
		st.ControlAddr = daemonAddr
	}
	client := &http.Client{Timeout: 500 * time.Millisecond}
	base := "http://" + st.ControlAddr

	switch args[0] {
	case "status":
		resp, err := apiReq(client, base, st.ControlToken, http.MethodGet, "/status", nil, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(os.Stdout, resp.Body)
		return nil
	case "ls":
		return runLS(client, base, st.ControlToken, args[1:])
	case "cat":
		if len(args) < 2 {
			return fmt.Errorf("usage: valetd cat <fs-path>")
		}
		if isHostPath(args[1]) {
			return fmt.Errorf("cat only handles fs paths, host path is not supported: %s", args[1])
		}
		q := url.Values{"path": []string{toFSPathArg(args[1])}}
		resp, err := apiReq(client, base, st.ControlToken, http.MethodGet, "/files", q, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(os.Stdout, resp.Body)
		return nil
	case "del":
		return runRM(client, base, st.ControlToken, args[1:])
	case "rm":
		return runRM(client, base, st.ControlToken, args[1:])
	case "mkdir":
		return runMkdir(client, base, st.ControlToken, args[1:])
	case "rmdir":
		return runRmdir(client, base, st.ControlToken, args[1:])
	case "mv":
		return runMV(client, base, st.ControlToken, args[1:])
	case "cp":
		return runCP(client, base, st.ControlToken, args[1:])
	case "completion":
		if len(args) < 2 || args[1] != "bash" {
			return fmt.Errorf("usage: valetd completion bash")
		}
		printBashCompletion()
		return nil
	case "__complete":
		return runComplete(client, base, st.ControlToken, args[1:])
	case "stop":
		_, err := apiReq(client, base, st.ControlToken, http.MethodPost, "/shutdown", nil, nil)
		return err
	}
	return nil
}

func loadRuntimeState(runPath string) (*runtimeState, error) {
	b, err := os.ReadFile(runPath)
	if err != nil {
		return nil, fmt.Errorf("Cannot connect to daemon. Please check if daemon is running.")
	}
	var st runtimeState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("Cannot connect to daemon. Please check if daemon is running.")
	}
	if st.ControlAddr == "" || st.ControlToken == "" {
		return nil, fmt.Errorf("Cannot connect to daemon. Please check if daemon is running.")
	}
	return &st, nil
}

func detectExistingDaemon(runtimeDir string) (bool, error) {
	st, err := loadRuntimeState(filepath.Join(runtimeDir, "runtime.json"))
	if err != nil {
		return false, nil
	}
	client := &http.Client{Timeout: 500 * time.Millisecond}
	_, err = apiReq(client, "http://"+st.ControlAddr, st.ControlToken, http.MethodGet, "/status", nil, nil)
	return err == nil, nil
}

func parseGlobalCLIOptions(args []string) (bool, string, []string) {
	if len(args) == 0 {
		return false, "", args
	}
	cmd := args[0]
	verbose := false
	daemonAddr := ""
	out := []string{cmd}
	for _, a := range args[1:] {
		if a == "-v" {
			verbose = true
			continue
		}
		if strings.HasPrefix(a, "--daemon-addr=") {
			daemonAddr = strings.TrimPrefix(a, "--daemon-addr=")
			continue
		}
		out = append(out, a)
	}
	return verbose, daemonAddr, out
}

func runLS(client *http.Client, base, token string, args []string) error {
	args = expandCombinedFlags(args, "al")
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	showAll := fs.Bool("a", false, "include hidden")
	long := fs.Bool("l", false, "long format")
	if err := fs.Parse(args); err != nil {
		return err
	}
	p := "/"
	if fs.NArg() > 0 {
		if isHostPath(fs.Arg(0)) {
			return fmt.Errorf("ls only handles fs paths, host path is not supported: %s", fs.Arg(0))
		}
		p = toFSPathArg(fs.Arg(0))
	}
	if isFile, err := fsPathIsFile(client, base, token, p); err == nil && isFile {
		_, _ = fmt.Fprintln(os.Stdout, path.Base(p))
		return nil
	}
	q := url.Values{"path": []string{p}, "list": []string{"1"}}
	if *showAll {
		q.Set("all", "1")
	}
	if *long {
		q.Set("detail", "1")
	}
	resp, err := apiReq(client, base, token, http.MethodGet, "/files", q, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if *long {
		var out struct {
			Items []struct {
				Name    string `json:"name"`
				IsDir   bool   `json:"is_dir"`
				Mode    string `json:"mode"`
				Size    int64  `json:"size"`
				ModTime string `json:"mod_time"`
			} `json:"items"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return err
		}
		for _, it := range out.Items {
			t := it.ModTime
			if len(t) >= 19 {
				t = t[:19]
			}
			suffix := ""
			if it.IsDir {
				suffix = "/"
			}
			_, _ = fmt.Fprintf(os.Stdout, "%s %8d %s %s%s\n", it.Mode, it.Size, t, it.Name, suffix)
		}
		return nil
	}
	var out struct {
		Items []string `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	for _, n := range out.Items {
		_, _ = fmt.Fprintln(os.Stdout, n)
	}
	return nil
}

func runCP(client *http.Client, base, token string, args []string) error {
	args = expandCombinedFlags(args, "rR")
	fs := flag.NewFlagSet("cp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	recursive := fs.Bool("r", false, "recursive")
	fs.BoolVar(recursive, "R", false, "recursive")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("usage: valetd cp [-r] <src> <dst>")
	}
	src, dst := fs.Arg(0), fs.Arg(1)
	srcHost := isHostPath(src)
	dstHost := isHostPath(dst)
	srcFS := !srcHost
	dstFS := !dstHost
	if srcFS && dstFS {
		srcFSPath := toFSPathArg(src)
		dstFSPath := toFSPathArg(dst)
		if fsPathExists(client, base, token, dstFSPath) {
			return fmt.Errorf("destination already exists: %s", dst)
		}
		payload := map[string]string{"from": srcFSPath}
		body, _ := json.Marshal(payload)
		q := url.Values{"path": []string{dstFSPath}}
		_, err := apiReq(client, base, token, http.MethodPost, "/files", q, bytes.NewReader(body))
		return err
	}
	if !srcFS && dstFS {
		st, err := os.Stat(src)
		if err != nil {
			return err
		}
		if st.IsDir() {
			if !*recursive {
				return fmt.Errorf("omitting directory %s (use -r)", src)
			}
			baseDst := toFSPathArg(dst)
			rootName := filepath.Base(src)
			if err := filepath.Walk(src, func(p string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				rel, err := filepath.Rel(src, p)
				if err != nil {
					return err
				}
				if rel == "." {
					return nil
				}
				fsPath := path.Join(baseDst, rootName, filepath.ToSlash(rel))
				if info.IsDir() {
					return nil
				}
				return writeHostFileToFS(client, base, token, p, fsPath)
			}); err != nil {
				return err
			}
			return nil
		}
		target := toFSPathArg(dst)
		if strings.HasSuffix(target, "/") || target == "/" || fsPathIsDir(client, base, token, target) {
			target = path.Join(target, filepath.Base(src))
		}
		if fsPathExists(client, base, token, target) {
			return fmt.Errorf("destination already exists: %s", target)
		}
		return writeHostFileToFS(client, base, token, src, target)
	}
	if srcFS && !dstFS {
		srcFSPath := toFSPathArg(src)
		if st, err := os.Stat(dst); err == nil && st.IsDir() {
			dst = filepath.Join(dst, path.Base(srcFSPath))
		}
		if _, err := os.Stat(dst); err == nil {
			return fmt.Errorf("destination already exists: %s", dst)
		}
		q := url.Values{"path": []string{srcFSPath}}
		resp, err := apiReq(client, base, token, http.MethodGet, "/files", q, nil)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o600)
	}
	return errors.New("cp requires at least one fs: path")
}

func runRM(client *http.Client, base, token string, args []string) error {
	args = expandCombinedFlags(args, "rR")
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	recursive := fs.Bool("r", false, "recursive")
	fs.BoolVar(recursive, "R", false, "recursive")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: valetd rm [-r] <fs-path>")
	}
	p := fs.Arg(0)
	if isHostPath(p) {
		return fmt.Errorf("rm only handles fs paths, host path is not supported: %s", p)
	}
	if !*recursive {
		isDir, err := fsPathIsDirWithErr(client, base, token, toFSPathArg(p))
		if err != nil {
			return err
		}
		if isDir {
			return fmt.Errorf("cannot remove directory without -r: %s", p)
		}
	}
	q := url.Values{"path": []string{toFSPathArg(p)}}
	if *recursive {
		q.Set("recursive", "1")
	}
	_, err := apiReq(client, base, token, http.MethodDelete, "/files", q, nil)
	return err
}

func runMkdir(client *http.Client, base, token string, args []string) error {
	args = expandCombinedFlags(args, "p")
	fs := flag.NewFlagSet("mkdir", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	parents := fs.Bool("p", false, "create parents")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: valetd mkdir [-p] <fs-path>")
	}
	p := fs.Arg(0)
	if isHostPath(p) {
		return fmt.Errorf("mkdir only handles fs paths, host path is not supported: %s", p)
	}
	q := url.Values{"path": []string{toFSPathArg(p)}}
	if *parents {
		q.Set("parents", "1")
	}
	_, err := apiReq(client, base, token, http.MethodPost, "/mkdir", q, nil)
	return err
}

func runRmdir(client *http.Client, base, token string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: valetd rmdir <fs-path>")
	}
	p := args[0]
	if isHostPath(p) {
		return fmt.Errorf("rmdir only handles fs paths, host path is not supported: %s", p)
	}
	q := url.Values{"path": []string{toFSPathArg(p)}}
	_, err := apiReq(client, base, token, http.MethodPost, "/rmdir", q, nil)
	return err
}

func runMV(client *http.Client, base, token string, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("usage: valetd mv <src> <dst>")
	}
	src, dst := args[0], args[1]
	srcHost := isHostPath(src)
	dstHost := isHostPath(dst)
	srcFS := !srcHost
	dstFS := !dstHost
	if srcFS && dstFS {
		srcFSPath := toFSPathArg(src)
		dstFSPath := toFSPathArg(dst)
		if fsPathExists(client, base, token, dstFSPath) {
			return fmt.Errorf("destination already exists: %s", dst)
		}
		if err := fsCopy(client, base, token, srcFSPath, dstFSPath); err != nil {
			return err
		}
		q := url.Values{"path": []string{srcFSPath}, "recursive": []string{"1"}}
		_, err := apiReq(client, base, token, http.MethodDelete, "/files", q, nil)
		return err
	}
	if srcHost && dstFS {
		if err := runCP(client, base, token, []string{src, dst}); err != nil {
			return err
		}
		return os.RemoveAll(src)
	}
	if srcFS && dstHost {
		if err := runCP(client, base, token, []string{src, dst}); err != nil {
			return err
		}
		q := url.Values{"path": []string{toFSPathArg(src)}, "recursive": []string{"1"}}
		_, err := apiReq(client, base, token, http.MethodDelete, "/files", q, nil)
		return err
	}
	return errors.New("mv requires at least one fs path")
}

func fsCopy(client *http.Client, base, token, src, dst string) error {
	isDir, err := fsPathIsDirWithErr(client, base, token, src)
	if err != nil {
		return err
	}
	if !isDir {
		payload := map[string]string{"from": src}
		body, _ := json.Marshal(payload)
		q := url.Values{"path": []string{dst}}
		_, err := apiReq(client, base, token, http.MethodPost, "/files", q, bytes.NewReader(body))
		return err
	}
	if _, err := apiReq(client, base, token, http.MethodPost, "/mkdir", url.Values{"path": []string{dst}, "parents": []string{"1"}}, nil); err != nil {
		return err
	}
	resp, err := apiReq(client, base, token, http.MethodGet, "/files", url.Values{"path": []string{src}, "list": []string{"1"}, "all": []string{"1"}}, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct {
		Items []string `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	for _, n := range out.Items {
		if err := fsCopy(client, base, token, path.Join(src, n), path.Join(dst, n)); err != nil {
			return err
		}
	}
	return nil
}

func runComplete(client *http.Client, base, token string, args []string) error {
	if len(args) == 0 {
		return nil
	}
	cmd := args[0]
	var cur string
	if len(args) > 1 {
		cur = args[len(args)-1]
	}
	suggest := []string{}
	switch cmd {
	case "ls", "cat", "del", "rm", "mkdir", "rmdir":
		suggest = append(suggest, completeFSPath(client, base, token, cur)...)
	case "cp", "mv":
		idx := len(args) - 1
		if idx <= 1 {
			if isHostPath(cur) {
				suggest = append(suggest, completeHostPath(cur)...)
			} else {
				suggest = append(suggest, completeFSPath(client, base, token, cur)...)
			}
		} else {
			if isHostPath(cur) {
				suggest = append(suggest, completeHostPath(cur)...)
			} else {
				suggest = append(suggest, completeFSPath(client, base, token, cur)...)
			}
		}
	}
	sort.Strings(suggest)
	for _, s := range suggest {
		_, _ = fmt.Fprintln(os.Stdout, s)
	}
	return nil
}

func writeHostFileToFS(client *http.Client, base, token, src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	payload := map[string]string{"content": string(data)}
	body, _ := json.Marshal(payload)
	q := url.Values{"path": []string{dst}}
	_, err = apiReq(client, base, token, http.MethodPost, "/files", q, bytes.NewReader(body))
	return err
}

func fsPathIsDir(client *http.Client, base, token, p string) bool {
	isDir, err := fsPathIsDirWithErr(client, base, token, p)
	return err == nil && isDir
}

func fsPathIsDirWithErr(client *http.Client, base, token, p string) (bool, error) {
	q := url.Values{"path": []string{p}, "meta": []string{"1"}}
	resp, err := apiReq(client, base, token, http.MethodGet, "/files", q, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var out struct {
		IsDir bool `json:"is_dir"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, err
	}
	return out.IsDir, nil
}

func fsPathIsFile(client *http.Client, base, token, p string) (bool, error) {
	isDir, err := fsPathIsDirWithErr(client, base, token, p)
	if err != nil {
		return false, err
	}
	return !isDir, nil
}

func fsPathExists(client *http.Client, base, token, p string) bool {
	_, err := fsPathIsDirWithErr(client, base, token, p)
	return err == nil
}

func apiReq(client *http.Client, base, token, method, path string, q url.Values, body io.Reader) (*http.Response, error) {
	u := base + path
	if q != nil {
		q.Set("token", token)
		u += "?" + q.Encode()
	} else {
		u += "?token=" + url.QueryEscape(token)
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		if cliVerbose {
			return nil, fmt.Errorf("connect failed (timeout 500ms): %w", err)
		}
		return nil, fmt.Errorf("Cannot connect to daemon. Please check if daemon is running.")
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("api %s %s failed: %s", method, path, strings.TrimSpace(string(msg)))
	}
	return resp, nil
}

func isHostPath(p string) bool {
	if strings.HasPrefix(p, "fs:") {
		return false
	}
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../")
}

func toFSPathArg(p string) string {
	p = strings.TrimPrefix(strings.TrimSpace(p), "fs:")
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "/"
	}
	return strings.TrimPrefix(p, "/")
}

func completeHostPath(cur string) []string {
	if cur == "" {
		cur = "./"
	}
	base := filepath.Dir(cur)
	if base == "." && strings.HasPrefix(cur, "./") {
		base = "./"
	}
	prefix := filepath.Base(cur)
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	out := make([]string, 0)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		cand := filepath.Join(base, name)
		if e.IsDir() {
			cand += "/"
		}
		out = append(out, cand)
	}
	return out
}

func completeFSPath(client *http.Client, base, token, cur string) []string {
	prefixOut := ""
	if strings.HasPrefix(cur, "fs:") {
		prefixOut = "fs:"
		cur = strings.TrimPrefix(cur, "fs:")
	}
	parent := ""
	prefix := cur
	if i := strings.LastIndex(cur, "/"); i >= 0 {
		parent = cur[:i]
		prefix = cur[i+1:]
	}
	q := url.Values{"path": []string{toFSPathArg(parent)}, "list": []string{"1"}, "all": []string{"1"}, "detail": []string{"1"}}
	resp, err := apiReq(client, base, token, http.MethodGet, "/files", q, nil)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out struct {
		Items []struct {
			Name  string `json:"name"`
			IsDir bool   `json:"is_dir"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil
	}
	res := make([]string, 0)
	for _, it := range out.Items {
		if !strings.HasPrefix(it.Name, prefix) {
			continue
		}
		cand := prefixOut + strings.TrimPrefix(path.Join(parent, it.Name), "/")
		if it.IsDir {
			cand += "/"
		}
		res = append(res, cand)
	}
	return res
}

func printBashCompletion() {
	_, _ = fmt.Fprint(os.Stdout, `# bash completion for valetd
_valetd_complete() {
  local cur prev words cword
  _init_completion || return
  if [[ ${#words[@]} -le 2 ]]; then
    COMPREPLY=( $(compgen -W "status ls cat cp mv rm mkdir rmdir completion" -- "$cur") )
    return
  fi
  local suggestions
  suggestions=$("${words[0]}" __complete "${words[@]:1}")
  COMPREPLY=( $(compgen -W "$suggestions" -- "$cur") )
}
complete -F _valetd_complete valetd
`)
}

func expandCombinedFlags(args []string, allowed string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if len(a) >= 3 && strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
			ok := true
			for _, r := range a[1:] {
				if !strings.ContainsRune(allowed, r) {
					ok = false
					break
				}
			}
			if ok {
				for _, r := range a[1:] {
					out = append(out, "-"+string(r))
				}
				continue
			}
		}
		out = append(out, a)
	}
	return out
}
