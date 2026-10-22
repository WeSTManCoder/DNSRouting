package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dnsrouting/configmanager"
	"dnsrouting/version"
)

const defaultEndpoint = "https://dnsrouting.gm-world.ru/packages/dnsrouting/updates.php"
const maxBinarySize int64 = 64 << 20
const flashSafetyReserve int64 = 256 << 10 // Leave 256 KiB free for overlay metadata and other writes.
const tmpSafetyReserve int64 = 1 << 20     // Keep at least 1 MiB free in /tmp (RAM-backed tmpfs).

var client = &http.Client{Timeout: 45 * time.Second}
var installMutex sync.Mutex

type Manifest struct {
	Version string `json:"version"`
	Arch    string `json:"arch"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}
type Status struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	Arch      string `json:"arch"`
}

func architecture() string {
	if runtime.GOARCH == "mips" || runtime.GOARCH == "mipsle" {
		if os.Getenv("GOMIPS") == "softfloat" {
			return runtime.GOARCH + "-softfloat"
		}
	}
	return runtime.GOARCH
}

// compare numerical versions without lexicographical mistakes (1.0.10 > 1.0.9).
func newer(a, b string) (bool, error) {
	valid := regexp.MustCompile(`^\d+(\.\d+){1,3}$`)
	if !valid.MatchString(a) || !valid.MatchString(b) {
		return false, errors.New("invalid version")
	}
	aa, bb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(aa) || i < len(bb); i++ {
		var av, bv uint64
		var err error
		if i < len(aa) {
			av, err = strconv.ParseUint(aa[i], 10, 32)
			if err != nil {
				return false, err
			}
		}
		if i < len(bb) {
			bv, err = strconv.ParseUint(bb[i], 10, 32)
			if err != nil {
				return false, err
			}
		}
		if av != bv {
			return av > bv, nil
		}
	}
	return false, nil
}

// ValidateEndpoint requires HTTPS and prohibits credentials and URL fragments.
func ValidateEndpoint(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errors.New("update server must be an HTTPS URL without credentials or fragment")
	}
	return nil
}

func updateEndpoint() string {
	endpoint := strings.TrimSpace(configmanager.Config.UpdateServer)
	if endpoint == "" {
		return defaultEndpoint
	}
	return endpoint
}

func fetch(ctx context.Context) (Manifest, Status, error) {
	arch := architecture()
	result := Status{Current: version.GetVersion(), Arch: arch}
	var manifest Manifest
	endpoint := updateEndpoint()
	if err := ValidateEndpoint(endpoint); err != nil {
		return manifest, result, err
	}
	u, _ := url.Parse(endpoint)
	q := u.Query()
	q.Set("arch", arch)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return manifest, result, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return manifest, result, err
	}
	defer resp.Body.Close()
	if resp.Request.URL.Scheme != "https" || !strings.EqualFold(resp.Request.URL.Hostname(), u.Hostname()) {
		return manifest, result, errors.New("unsafe redirect")
	}
	if resp.StatusCode != 200 {
		return manifest, result, fmt.Errorf("update server HTTP %d", resp.StatusCode)
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&manifest); err != nil {
		return manifest, result, err
	}
	if manifest.Arch != arch {
		return manifest, result, fmt.Errorf("architecture mismatch: %s", manifest.Arch)
	}
	checksum := regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	if !checksum.MatchString(manifest.SHA256) {
		return manifest, result, errors.New("invalid SHA256")
	}
	target, err := url.Parse(manifest.URL)
	if err != nil || target.Scheme != "https" || !strings.EqualFold(target.Hostname(), u.Hostname()) || target.User != nil {
		return manifest, result, errors.New("untrusted download URL")
	}
	available, err := newer(manifest.Version, result.Current)
	if err != nil {
		return manifest, result, err
	}
	result.Latest = manifest.Version
	result.Available = available
	return manifest, result, nil
}
func Check(ctx context.Context) (Status, error) { _, status, err := fetch(ctx); return status, err }

func Install(ctx context.Context) (Status, error) {
	if !installMutex.TryLock() {
		return Status{}, errors.New("installation already in progress")
	}
	defer installMutex.Unlock()
	manifest, status, err := fetch(ctx)
	if err != nil || !status.Available {
		return status, err
	}
	executable, err := os.Executable()
	if err != nil {
		return status, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return status, err
	}
	if st, err := os.Stat("/etc/init.d/dnsrouting"); err != nil || st.Mode()&0111 == 0 {
		return status, errors.New("missing executable /etc/init.d/dnsrouting")
	}
	file, err := os.CreateTemp("/tmp", "dnsrouting-update-*")
	if err != nil {
		return status, err
	}
	tmpName := file.Name()
	keepDownload := false
	defer func() {
		if !keepDownload {
			os.Remove(tmpName)
		}
	}()
	defer file.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifest.URL, nil)
	if err != nil {
		return status, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return status, err
	}
	defer resp.Body.Close()
	downloadURL, parseErr := url.Parse(manifest.URL)
	if parseErr != nil || resp.Request.URL.Scheme != "https" || !strings.EqualFold(resp.Request.URL.Hostname(), downloadURL.Hostname()) {
		return status, errors.New("unsafe download redirect")
	}
	if resp.StatusCode != 200 {
		return status, fmt.Errorf("download HTTP %d", resp.StatusCode)
	}
	// Check /tmp before downloading: Content-Length is only a hint, so also
	// check free space on every write. Never exhaust router RAM/tmpfs.
	if resp.ContentLength > maxBinarySize {
		return status, errors.New("invalid binary size")
	}
	if resp.ContentLength > 0 {
		if err := ensureSpace("/tmp", resp.ContentLength, tmpSafetyReserve, "temporary storage"); err != nil {
			return status, err
		}
	} else if err := ensureSpace("/tmp", 1, tmpSafetyReserve, "temporary storage"); err != nil {
		return status, err
	}
	hash := sha256.New()
	writer := &spaceCheckedWriter{file: file, directory: "/tmp"}
	size, err := io.Copy(io.MultiWriter(writer, hash), io.LimitReader(resp.Body, maxBinarySize+1))
	if err != nil {
		return status, err
	}
	if size == 0 || size > maxBinarySize {
		return status, errors.New("invalid binary size")
	}
	if !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), manifest.SHA256) {
		return status, errors.New("SHA256 mismatch")
	}
	if err = file.Chmod(0755); err != nil {
		return status, err
	}
	if err = file.Sync(); err != nil {
		return status, err
	}
	if err = file.Close(); err != nil {
		return status, err
	}
	// Check the destination filesystem before stopping the running DNS service.
	// Deliberately do not count the old executable as reclaimable space:
	// on OpenWrt it may live in read-only squashfs, and unlinking it cannot
	// free flash space. Reject uncertain updates instead of risking downtime.
	if err = ensureFlashSpace(filepath.Dir(executable), size); err != nil {
		return status, err
	}

	// A running Linux executable cannot be overwritten (ETXTBSY). Also, on
	// squashfs+overlay OpenWrt, truncating /usr/bin/dnsrouting can trigger a
	// copy-up of the old binary, consuming space for both versions.
	// A detached helper first stops the daemon and unlinks the old path,
	// then copies the verified binary directly from RAM into its final path.
	// There is intentionally no backup and no on-flash staging file.
	helper, err := os.CreateTemp("/tmp", "dnsrouting-install-*.sh")
	if err != nil {
		return status, err
	}
	helperName := helper.Name()
	const script = `#!/bin/sh
set -eu
binary="$1"
source="$2"
service=/etc/init.d/dnsrouting
required_kb="$3"
sleep 2
# Recheck immediately before stopping the service: another process might
# have consumed overlay space since the Go-side preflight check.
# BusyBox df -Pk reports available KiB on the target mounted filesystem.
free_kb=$(df -Pk "$(dirname "$binary")" | awk 'NR==2 {print $4}')
case "$free_kb" in
  ''|*[!0-9]*) echo "DNSRouting update: cannot check destination free space" >&2; exit 1 ;;
esac
if [ "$free_kb" -lt "$required_kb" ]; then
  echo "DNSRouting update: insufficient overlay space (need ${required_kb} KiB, have ${free_kb} KiB); old binary untouched" >&2
  exit 1
fi
"$service" stop
# Do not write over a running file or copy up the old squashfs image.
rm -f -- "$binary"
if ! cp -- "$source" "$binary"; then
  echo "DNSRouting update: copy failed; verified image kept at $source" >&2
  exit 1
fi
chmod 755 "$binary"
sync
"$service" start
rm -f -- "$source" "$0"
`
	if _, err = io.WriteString(helper, script); err != nil {
		helper.Close()
		os.Remove(helperName)
		return status, err
	}
	if err = helper.Chmod(0700); err != nil {
		helper.Close()
		os.Remove(helperName)
		return status, err
	}
	if err = helper.Close(); err != nil {
		os.Remove(helperName)
		return status, err
	}
	// The detached installer survives the DNSRouting service being stopped.
	// Use an independent session, not a child sharing the daemon's session.
	requiredKiB := (size + flashSafetyReserve + 1023) / 1024
	cmd := exec.Command("/bin/sh", helperName, executable, tmpName, strconv.FormatInt(requiredKiB, 10))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err = cmd.Start(); err != nil {
		os.Remove(helperName)
		return status, fmt.Errorf("start detached installer: %w", err)
	}
	_ = cmd.Process.Release()
	// The detached helper owns the downloaded file from this point on.
	// It cleans it only after a successful service restart.
	keepDownload = true

	return status, nil
}

func Start() {
	go func() {
		// Run first check on startup, then repeat once per day. A failed check retries next day.
		check := func() {
			if !configmanager.Config.AutoUpdate {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			status, err := Check(ctx)
			if err != nil {
				fmt.Println("[Updater] check:", err)
				return
			}
			if status.Available {
				fmt.Printf("[Updater] installing %s -> %s\n", status.Current, status.Latest)
				if _, err := Install(ctx); err != nil {
					fmt.Println("[Updater] install:", err)
				}
			}
		}
		check()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			check()
		}
	}()
}

// spaceCheckedWriter prevents a download from filling the /tmp filesystem.
// The filesystem is checked before each write, including chunked responses or
// servers reporting an incorrect Content-Length. The incomplete file is removed
// by Install's deferred cleanup on failure.
type spaceCheckedWriter struct {
	file      *os.File
	directory string
}

func (w *spaceCheckedWriter) Write(p []byte) (int, error) {
	if err := ensureSpace(w.directory, int64(len(p)), tmpSafetyReserve, "temporary storage"); err != nil {
		return 0, err
	}
	return w.file.Write(p)
}

func ensureSpace(directory string, bytesNeeded, reserve int64, name string) error {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(directory, &fs); err != nil {
		return fmt.Errorf("check available %s space: %w", name, err)
	}
	available := uint64(fs.Bavail) * uint64(fs.Bsize)
	required := uint64(bytesNeeded + reserve)
	if available < required {
		return fmt.Errorf("insufficient %s space: need %d bytes (including reserve), available %d bytes; current binary was not changed", name, required, available)
	}
	return nil
}

// ensureFlashSpace checks the writable destination filesystem, not /tmp.
// Statfs.Bavail excludes blocks reserved for privileged filesystem maintenance.
func ensureFlashSpace(directory string, binarySize int64) error {
	return ensureSpace(directory, binarySize, flashSafetyReserve, "flash")
}
