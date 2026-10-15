// SPDX-License-Identifier: GPL-2.0-only

package lab

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/KDDIR-SEC/memento/internal/prnlog"
	"github.com/KDDIR-SEC/memento/internal/simcrypto"
	"github.com/KDDIR-SEC/memento/internal/state"
	"golang.org/x/sys/unix"
)

const MarkerName = ".memento-lab"

var scenarioPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

//go:embed fixtures/*
var fixtures embed.FS

type Marker struct {
	Schema            string    `json:"schema"`
	UUID              string    `json:"uuid"`
	CanonicalRoot     string    `json:"canonical_root"`
	AllowedExtensions []string  `json:"allowed_extensions"`
	CreatedAt         time.Time `json:"created_at"`
}

type FileRecord struct {
	Path      string `json:"path"`
	Extension string `json:"extension"`
	Size      int64  `json:"size"`
	Inode     uint64 `json:"inode"`
	MtimeNS   int64  `json:"mtime_ns"`
	SHA256    string `json:"sha256"`
}

type Manifest struct {
	Schema             string       `json:"schema"`
	Scenario           string       `json:"scenario"`
	ScenarioUUID       string       `json:"scenario_uuid"`
	CanonicalRoot      string       `json:"canonical_root"`
	Extensions         []string     `json:"extensions"`
	Files              []FileRecord `json:"files"`
	TotalFiles         int          `json:"total_files"`
	TotalBytes         int64        `json:"total_bytes"`
	EncryptedOutputDir string       `json:"encrypted_output_dir"`
	CreatedAt          time.Time    `json:"created_at"`
	Digest             string       `json:"digest"`
}

type Manager struct {
	State state.Layout
}

func (m Manager) Init(scenario string, allowExtensions []string) (Marker, error) {
	if err := validateScenario(scenario); err != nil {
		return Marker{}, err
	}
	extensions, err := normalizeExtensions(allowExtensions)
	if err != nil {
		return Marker{}, err
	}
	if len(extensions) == 0 {
		return Marker{}, errors.New("at least one allowed extension is required")
	}
	if err := m.State.Ensure(); err != nil {
		return Marker{}, err
	}
	root := filepath.Join(m.State.Lab, scenario)
	if err := os.Mkdir(root, 0o700); err != nil {
		return Marker{}, fmt.Errorf("create scenario: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(filepath.Join(root, MarkerName))
			_ = os.Remove(filepath.Join(root, "work"))
			_ = os.Remove(filepath.Join(root, "encrypted"))
			_ = os.Remove(filepath.Join(root, "plans"))
			_ = os.Remove(root)
		}
	}()
	for _, child := range []string{"work", "encrypted", "plans"} {
		if err := os.Mkdir(filepath.Join(root, child), 0o700); err != nil {
			return Marker{}, fmt.Errorf("create scenario directory: %w", err)
		}
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return Marker{}, err
	}
	uuid, err := newUUID()
	if err != nil {
		return Marker{}, err
	}
	marker := Marker{Schema: "memento.lab/v1", UUID: uuid, CanonicalRoot: canonical, AllowedExtensions: extensions, CreatedAt: time.Now().UTC()}
	if err := writeJSONExclusive(filepath.Join(root, MarkerName), marker); err != nil {
		return Marker{}, err
	}
	cleanup = false
	return marker, nil
}

func (m Manager) Create(scenario, fixtureName string) (string, error) {
	root, _, err := m.loadScenario(scenario)
	if err != nil {
		return "", err
	}
	if fixtureName == "" {
		fixtureName = "sample.txt"
	}
	if filepath.Base(fixtureName) != fixtureName || strings.HasPrefix(fixtureName, ".") {
		return "", errors.New("fixture name must be a visible base name")
	}
	data, err := fixtures.ReadFile("fixtures/" + fixtureName)
	if err != nil {
		return "", fmt.Errorf("unknown managed fixture %q", fixtureName)
	}
	return writeFixture(root, fixtureName, data)
}

// CreateCopies supports the v1 create compatibility route while retaining the
// same embedded-fixture-only boundary. It never accepts a source path.
func (m Manager) CreateCopies(scenario, fixtureName, extension string, count int) ([]string, error) {
	root, marker, err := m.loadScenario(scenario)
	if err != nil {
		return nil, err
	}
	if count < 1 || count > 1000 {
		return nil, errors.New("fixture copy count must be between 1 and 1000")
	}
	extensions, err := normalizeExtensions([]string{extension})
	if err != nil || len(extensions) != 1 {
		return nil, fmt.Errorf("invalid fixture extension %q", extension)
	}
	if err := requireAllowed(extensions, marker.AllowedExtensions); err != nil {
		return nil, err
	}
	data, err := fixtures.ReadFile("fixtures/" + fixtureName)
	if err != nil {
		return nil, fmt.Errorf("unknown managed fixture %q", fixtureName)
	}
	paths := make([]string, 0, count)
	for index := 0; index < count; index++ {
		name := fmt.Sprintf("fixture-%04d%s", index, extensions[0])
		path, err := writeFixture(root, name, data)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

func writeFixture(root, destinationName string, data []byte) (string, error) {
	if filepath.Base(destinationName) != destinationName || strings.HasPrefix(destinationName, ".") {
		return "", errors.New("fixture destination must be a visible base name")
	}
	workPath := filepath.Join(root, "work")
	workFD, err := unix.Open(workPath, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("open fixture work directory: %w", err)
	}
	defer unix.Close(workFD)
	fd, err := unix.Openat2(workFD, destinationName, &unix.OpenHow{
		Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Mode:  0o600, Resolve: resolveFlags,
	})
	if err != nil {
		return "", fmt.Errorf("create fixture copy: %w", err)
	}
	destination := filepath.Join(workPath, destinationName)
	f := os.NewFile(uintptr(fd), destination)
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return "", err
	}
	return destination, nil
}

func (m Manager) Plan(scenario string, requestedExtensions []string) (Manifest, string, error) {
	root, marker, err := m.loadScenario(scenario)
	if err != nil {
		return Manifest{}, "", err
	}
	extensions, err := normalizeExtensions(requestedExtensions)
	if err != nil {
		return Manifest{}, "", err
	}
	if len(extensions) == 0 {
		return Manifest{}, "", errors.New("plan-encryption requires one or more explicit extensions")
	}
	if err := requireAllowed(extensions, marker.AllowedExtensions); err != nil {
		return Manifest{}, "", err
	}
	files, total, canonicalWork, err := collect(filepath.Join(root, "work"), extensions)
	if err != nil {
		return Manifest{}, "", err
	}
	if len(files) == 0 {
		return Manifest{}, "", errors.New("no regular fixture files matched the requested extensions")
	}
	manifest := Manifest{
		Schema:             "memento.encryption-manifest/v1",
		Scenario:           scenario,
		ScenarioUUID:       marker.UUID,
		CanonicalRoot:      canonicalWork,
		Extensions:         extensions,
		Files:              files,
		TotalFiles:         len(files),
		TotalBytes:         total,
		EncryptedOutputDir: filepath.Join(root, "encrypted"),
		CreatedAt:          time.Now().UTC(),
	}
	digest, err := manifestDigest(manifest)
	if err != nil {
		return Manifest{}, "", err
	}
	manifest.Digest = digest
	path := filepath.Join(root, "plans", "encryption-"+digest+".json")
	if err := writeJSONExclusive(path, manifest); err != nil {
		return Manifest{}, "", err
	}
	return manifest, path, nil
}

func (m Manager) LoadManifest(scenario, path string) (Manifest, error) {
	root, marker, err := m.loadScenario(scenario)
	if err != nil {
		return Manifest{}, err
	}
	canonicalPlans, err := filepath.EvalSymlinks(filepath.Join(root, "plans"))
	if err != nil {
		return Manifest{}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return Manifest{}, err
	}
	if filepath.Dir(abs) != canonicalPlans || filepath.Base(abs) != filepath.Base(path) {
		return Manifest{}, errors.New("manifest must be a direct child of the scenario plans directory")
	}
	plansFD, err := unix.Open(canonicalPlans, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Manifest{}, err
	}
	defer unix.Close(plansFD)
	fd, err := openBeneath(plansFD, filepath.Base(abs), unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return Manifest{}, fmt.Errorf("secure-open manifest: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		unix.Close(fd)
		return Manifest{}, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		unix.Close(fd)
		return Manifest{}, errors.New("manifest is not a single-link regular file")
	}
	f := os.NewFile(uintptr(fd), abs)
	defer f.Close()
	manifest, err := decodeManifest(f)
	if err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := validateManifestForScenario(root, scenario, marker, manifest); err != nil {
		return Manifest{}, err
	}
	if filepath.Base(abs) != "encryption-"+manifest.Digest+".json" {
		return Manifest{}, errors.New("manifest digest mismatch")
	}
	return manifest, nil
}

func (m Manager) Revalidate(scenario string, manifest Manifest) error {
	root, marker, err := m.loadScenario(scenario)
	if err != nil {
		return err
	}
	if err := validateManifestForScenario(root, scenario, marker, manifest); err != nil {
		return err
	}
	files, total, canonical, err := collect(filepath.Join(root, "work"), manifest.Extensions)
	if err != nil {
		return err
	}
	if canonical != manifest.CanonicalRoot || total != manifest.TotalBytes || len(files) != manifest.TotalFiles {
		return errors.New("manifest invalidated: target set changed")
	}
	if !equalFiles(files, manifest.Files) {
		return errors.New("manifest invalidated: a target was added, removed, or modified")
	}
	return nil
}

type ExecuteOptions struct {
	Scenario               string
	Manifest               Manifest
	Algorithm              string
	Input                  *os.File
	Output                 *os.File
	Confirmation           io.Writer
	PRNLogPath             string
	BabukKey               []byte
	ValidationStopAfterPRN bool
}

// Execute is the only filesystem encryption entry point. It always requires a
// real terminal and an exact YES approval after displaying every target. No
// bypass flag exists.
func (m Manager) Execute(options ExecuteOptions) error {
	if options.Algorithm != "babuk" && options.Algorithm != "qilin" {
		return fmt.Errorf("unsupported simulator %q", options.Algorithm)
	}
	if options.Algorithm == "babuk" && len(options.BabukKey) != 32 {
		return errors.New("Babuk master public key must be 32 bytes")
	}
	if options.ValidationStopAfterPRN {
		if err := validatePRNStop(options.Algorithm, os.Geteuid(), validateCurrentRootlessContainer); err != nil {
			return err
		}
	}
	terminal := options.Input != nil && isTerminal(int(options.Input.Fd()))
	if err := checkExecutionGate(os.Geteuid(), terminal); err != nil {
		return err
	}
	if options.Output == nil {
		options.Output = os.Stdout
	}
	if options.Confirmation == nil {
		options.Confirmation = options.Output
	}
	if err := m.Revalidate(options.Scenario, options.Manifest); err != nil {
		return err
	}
	if err := requestEncryptionApproval(options.Input, options.Confirmation, options.Manifest); err != nil {
		return err
	}
	// The target set is checked again after the human confirmation so a long
	// review interval cannot be used to swap inputs.
	if err := m.Revalidate(options.Scenario, options.Manifest); err != nil {
		return err
	}
	return m.executeApproved(options)
}

func requestEncryptionApproval(input io.Reader, output io.Writer, manifest Manifest) error {
	fmt.Fprintf(output, "Scenario root: %s\nExtensions: %s\nFiles: %d\nTotal bytes: %d\nOutput: %s\nTargets:\n", manifest.CanonicalRoot, strings.Join(manifest.Extensions, ","), manifest.TotalFiles, manifest.TotalBytes, manifest.EncryptedOutputDir)
	for _, file := range manifest.Files {
		fmt.Fprintf(output, "  %s (%d bytes, SHA-256 %s)\n", file.Path, file.Size, file.SHA256)
	}
	fmt.Fprint(output, "Proceed with encryption? Type YES to continue or NO to cancel:\n> ")
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read encryption approval: %w; no files were encrypted", err)
	}
	response := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	switch response {
	case "YES":
		return nil
	case "NO":
		fmt.Fprintln(output, "Encryption cancelled; no files were created.")
		return errors.New("encryption declined; no files were encrypted")
	default:
		return errors.New("approval must be exactly YES or NO; no files were encrypted")
	}
}

func validatePRNStop(algorithm string, euid int, validateContainer func() error) error {
	if algorithm != "babuk" {
		return errors.New("validation PRN stop is only supported for Babuk")
	}
	if euid != 0 {
		return errors.New("validation PRN stop requires namespaced root in the rootless container")
	}
	if err := validateContainer(); err != nil {
		return fmt.Errorf("validation PRN stop requires the attested rootless container: %w", err)
	}
	return nil
}

func (m Manager) executeApproved(options ExecuteOptions) error {
	root, _, err := m.loadScenario(options.Scenario)
	if err != nil {
		return err
	}
	workRoot := filepath.Join(root, "work")
	outputRoot := filepath.Join(root, "encrypted")
	workFD, err := unix.Open(workRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(workFD)
	outputFD, err := unix.Open(outputRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(outputFD)

	for _, record := range options.Manifest.Files {
		if err := mkdirParentsAt(outputFD, filepath.Dir(record.Path)); err != nil {
			return err
		}
		outRel := record.Path + suffixFor(options.Algorithm)
		if existingFD, err := unix.Openat2(outputFD, outRel, &unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: resolveFlags}); err == nil {
			_ = unix.Close(existingFD)
			return fmt.Errorf("refusing to overwrite existing output %q", outRel)
		} else if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("inspect output %q: %w", outRel, err)
		}
	}

	logWriter, err := prnlog.NewWriter(options.PRNLogPath)
	if err != nil {
		return fmt.Errorf("open lab PRN log: %w", err)
	}
	defer logWriter.Close()
	validationStopped := false
	sink := func(operation string, value []byte) error {
		if err := logWriter.Write(prnlog.Record{Schema: prnlog.Schema, Time: time.Now().UTC(), Source: "lab", Operation: operation, ValueHex: hex.EncodeToString(value), CapturedLength: len(value), RequestedLength: len(value)}); err != nil {
			return err
		}
		if options.ValidationStopAfterPRN && !validationStopped {
			validationStopped = true
			if err := unix.Kill(os.Getpid(), unix.SIGSTOP); err != nil {
				return fmt.Errorf("stop after validation PRN: %w", err)
			}
		}
		return nil
	}

	for _, record := range options.Manifest.Files {
		inFD, err := openBeneath(workFD, record.Path, unix.O_RDONLY|unix.O_CLOEXEC)
		if err != nil {
			return fmt.Errorf("open approved input %q: %w", record.Path, err)
		}
		in := os.NewFile(uintptr(inFD), record.Path)
		if err := verifyOpenFile(in, record); err != nil {
			_ = in.Close()
			return err
		}
		outRel := record.Path + suffixFor(options.Algorithm)
		outFD, err := unix.Openat2(outputFD, outRel, &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC, Mode: 0o600, Resolve: resolveFlags})
		if err != nil {
			_ = in.Close()
			return fmt.Errorf("create output %q: %w", outRel, err)
		}
		out := os.NewFile(uintptr(outFD), outRel)
		switch options.Algorithm {
		case "babuk":
			err = simcrypto.TransformBabuk(out, in, simcrypto.BabukOptions{MasterPublicKey: options.BabukKey, PRN: sink})
		case "qilin":
			err = simcrypto.TransformQilin(out, in, simcrypto.QilinOptions{PRN: sink})
		default:
			err = fmt.Errorf("unsupported simulator %q", options.Algorithm)
		}
		var syncErr error
		if err == nil {
			syncErr = out.Sync()
		}
		closeErr := errors.Join(in.Close(), out.Close())
		if transformErr := errors.Join(err, syncErr, closeErr); transformErr != nil {
			_ = unix.Unlinkat(outputFD, outRel, 0)
			return fmt.Errorf("transform %q: %w", record.Path, transformErr)
		}
	}
	return nil
}

const resolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV

func collect(workRoot string, extensions []string) ([]FileRecord, int64, string, error) {
	canonical, err := filepath.EvalSymlinks(workRoot)
	if err != nil {
		return nil, 0, "", err
	}
	rootInfo, err := os.Stat(canonical)
	if err != nil {
		return nil, 0, "", err
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, 0, "", errors.New("cannot read root inode metadata")
	}
	rootFD, err := unix.Open(canonical, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, "", err
	}
	defer unix.Close(rootFD)
	wanted := make(map[string]bool, len(extensions))
	for _, extension := range extensions {
		wanted[extension] = true
	}
	var files []FileRecord
	var total int64
	err = filepath.WalkDir(canonical, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == canonical {
			return nil
		}
		rel, err := filepath.Rel(canonical, path)
		if err != nil {
			return err
		}
		for _, component := range strings.Split(rel, string(filepath.Separator)) {
			if strings.HasPrefix(component, ".") {
				return fmt.Errorf("hidden path is forbidden in lab work tree: %q", rel)
			}
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint64(stat.Dev) != uint64(rootStat.Dev) {
			return fmt.Errorf("mount boundary is forbidden: %q", rel)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic links are forbidden: %q", rel)
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("special files are forbidden: %q", rel)
		}
		if stat.Nlink != 1 {
			return fmt.Errorf("hard-linked files are forbidden: %q", rel)
		}
		extension := strings.ToLower(filepath.Ext(entry.Name()))
		if !wanted[extension] {
			return nil
		}
		fd, err := openBeneath(rootFD, rel, unix.O_RDONLY|unix.O_CLOEXEC)
		if err != nil {
			return fmt.Errorf("secure-open %q: %w", rel, err)
		}
		file := os.NewFile(uintptr(fd), rel)
		var before unix.Stat_t
		if err := unix.Fstat(fd, &before); err != nil {
			_ = file.Close()
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, file)
		var after unix.Stat_t
		statErr := unix.Fstat(fd, &after)
		closeErr := file.Close()
		if err := errors.Join(copyErr, statErr, closeErr); err != nil {
			return err
		}
		if before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim || after.Ino != stat.Ino || after.Size != info.Size() || after.Mtim.Sec != stat.Mtim.Sec || after.Mtim.Nsec != stat.Mtim.Nsec {
			return fmt.Errorf("file changed while planning: %q", rel)
		}
		record := FileRecord{Path: filepath.ToSlash(rel), Extension: extension, Size: after.Size, Inode: after.Ino, MtimeNS: after.Mtim.Sec*1e9 + after.Mtim.Nsec, SHA256: hex.EncodeToString(hash.Sum(nil))}
		files = append(files, record)
		total += after.Size
		return nil
	})
	if err != nil {
		return nil, 0, "", err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, total, canonical, nil
}

func (m Manager) loadScenario(scenario string) (string, Marker, error) {
	if err := validateScenario(scenario); err != nil {
		return "", Marker{}, err
	}
	root := filepath.Join(m.State.Lab, scenario)
	info, err := os.Lstat(root)
	if err != nil {
		return "", Marker{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", Marker{}, errors.New("scenario root must be a real directory")
	}
	canonicalLab, err := filepath.EvalSymlinks(m.State.Lab)
	if err != nil {
		return "", Marker{}, err
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", Marker{}, err
	}
	if filepath.Dir(canonical) != canonicalLab {
		return "", Marker{}, errors.New("scenario root escaped the state lab directory")
	}
	rootStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", Marker{}, errors.New("cannot inspect scenario mount")
	}
	for _, child := range []string{"work", "encrypted", "plans"} {
		path := filepath.Join(root, child)
		childInfo, err := os.Lstat(path)
		if err != nil || !childInfo.IsDir() || childInfo.Mode()&os.ModeSymlink != 0 {
			return "", Marker{}, fmt.Errorf("scenario %s must be a real directory", child)
		}
		childCanonical, err := filepath.EvalSymlinks(path)
		if err != nil || childCanonical != filepath.Join(canonical, child) {
			return "", Marker{}, fmt.Errorf("scenario %s escaped its canonical root", child)
		}
		childStat, ok := childInfo.Sys().(*syscall.Stat_t)
		if !ok || uint64(childStat.Dev) != uint64(rootStat.Dev) {
			return "", Marker{}, fmt.Errorf("scenario %s crosses a mount boundary", child)
		}
	}
	rootFD, err := unix.Open(canonical, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", Marker{}, err
	}
	defer unix.Close(rootFD)
	markerFD, err := openBeneath(rootFD, MarkerName, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return "", Marker{}, errors.New("scenario is missing a secure .memento-lab marker")
	}
	var markerStat unix.Stat_t
	if err := unix.Fstat(markerFD, &markerStat); err != nil {
		unix.Close(markerFD)
		return "", Marker{}, err
	}
	if markerStat.Mode&unix.S_IFMT != unix.S_IFREG || markerStat.Nlink != 1 ||
		uint64(markerStat.Dev) != uint64(rootStat.Dev) {
		unix.Close(markerFD)
		return "", Marker{}, errors.New("scenario is missing a single-link regular .memento-lab marker")
	}
	markerPath := filepath.Join(root, MarkerName)
	markerFile := os.NewFile(uintptr(markerFD), markerPath)
	data, readErr := io.ReadAll(io.LimitReader(markerFile, 64*1024+1))
	closeErr := markerFile.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return "", Marker{}, err
	}
	if len(data) > 64*1024 {
		return "", Marker{}, errors.New("lab marker exceeds 64 KiB")
	}
	var marker Marker
	if err := decodeStrict(data, &marker); err != nil {
		return "", Marker{}, fmt.Errorf("decode lab marker: %w", err)
	}
	if marker.Schema != "memento.lab/v1" || marker.UUID == "" || marker.CanonicalRoot != canonical {
		return "", Marker{}, errors.New("lab marker does not match its canonical scenario root")
	}
	normalizedAllowed, err := normalizeExtensions(marker.AllowedExtensions)
	if err != nil || len(normalizedAllowed) == 0 || !equalStrings(normalizedAllowed, marker.AllowedExtensions) {
		return "", Marker{}, errors.New("lab marker contains a non-canonical extension allowlist")
	}
	return canonical, marker, nil
}

func validateScenario(value string) error {
	if !scenarioPattern.MatchString(value) || value == "." || value == ".." {
		return fmt.Errorf("invalid scenario name %q", value)
	}
	return nil
}

func normalizeExtensions(values []string) ([]string, error) {
	seen := make(map[string]bool)
	var result []string
	for _, group := range values {
		for _, value := range strings.Split(group, ",") {
			value = strings.ToLower(strings.TrimSpace(value))
			if value == "" {
				continue
			}
			if !strings.HasPrefix(value, ".") || strings.ContainsAny(value, `/\\`) || len(value) < 2 {
				return nil, fmt.Errorf("invalid extension %q", value)
			}
			if !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
	}
	sort.Strings(result)
	return result, nil
}

func requireAllowed(requested, allowed []string) error {
	set := make(map[string]bool, len(allowed))
	for _, extension := range allowed {
		set[extension] = true
	}
	for _, extension := range requested {
		if !set[extension] {
			return fmt.Errorf("extension %q is not in the scenario allowlist", extension)
		}
	}
	return nil
}

func validateManifestForScenario(root, scenario string, marker Marker, manifest Manifest) error {
	if manifest.Schema != "memento.encryption-manifest/v1" || manifest.Scenario != scenario || manifest.ScenarioUUID != marker.UUID {
		return errors.New("manifest does not belong to this scenario")
	}
	normalized, err := normalizeExtensions(manifest.Extensions)
	if err != nil || len(normalized) == 0 || !equalStrings(normalized, manifest.Extensions) {
		return errors.New("manifest contains a non-canonical extension list")
	}
	if err := requireAllowed(normalized, marker.AllowedExtensions); err != nil {
		return fmt.Errorf("manifest exceeds the scenario extension allowlist: %w", err)
	}
	canonicalWork, err := filepath.EvalSymlinks(filepath.Join(root, "work"))
	if err != nil {
		return err
	}
	canonicalOutput, err := filepath.EvalSymlinks(filepath.Join(root, "encrypted"))
	if err != nil {
		return err
	}
	if manifest.CanonicalRoot != canonicalWork || manifest.EncryptedOutputDir != canonicalOutput {
		return errors.New("manifest input or output root does not match the scenario")
	}
	if len(manifest.Files) == 0 || manifest.TotalFiles != len(manifest.Files) || manifest.TotalBytes < 0 {
		return errors.New("manifest file totals are invalid")
	}
	want, err := manifestDigest(manifest)
	if err != nil {
		return err
	}
	if manifest.Digest != want {
		return errors.New("manifest digest mismatch")
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func writeJSONExclusive(path string, value any) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(value)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
}

func decodeManifest(r io.Reader) (Manifest, error) {
	data, err := io.ReadAll(io.LimitReader(r, 4*1024*1024+1))
	if err != nil {
		return Manifest{}, err
	}
	if len(data) > 4*1024*1024 {
		return Manifest{}, errors.New("manifest exceeds 4 MiB")
	}
	var manifest Manifest
	if err := decodeStrict(data, &manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing data")
	}
	return nil
}

func manifestDigest(manifest Manifest) (string, error) {
	manifest.Digest = ""
	data, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func equalFiles(left, right []FileRecord) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func openBeneath(rootFD int, relative string, flags uint64) (int, error) {
	if filepath.IsAbs(relative) || relative == "." || strings.Contains(relative, "..") {
		return -1, errors.New("unsafe relative path")
	}
	return unix.Openat2(rootFD, filepath.FromSlash(relative), &unix.OpenHow{Flags: flags | unix.O_NOFOLLOW, Resolve: resolveFlags})
}

func verifyOpenFile(file *os.File, record FileRecord) error {
	var before unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &before); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Ino != record.Inode ||
		before.Size != record.Size || before.Mtim.Sec*1e9+before.Mtim.Nsec != record.MtimeNS {
		return fmt.Errorf("manifest invalidated immediately before opening %q", record.Path)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return err
	}
	if before.Nlink != 1 || after.Nlink != 1 || before.Ino != after.Ino || before.Size != after.Size ||
		before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return fmt.Errorf("manifest invalidated while reading %q", record.Path)
	}
	if hex.EncodeToString(hash.Sum(nil)) != record.SHA256 {
		return fmt.Errorf("manifest invalidated: digest changed for %q", record.Path)
	}
	_, err := file.Seek(0, io.SeekStart)
	return err
}

func mkdirParentsAt(rootFD int, relative string) error {
	if relative == "." || relative == "" {
		return nil
	}
	current := ""
	for _, component := range strings.Split(filepath.ToSlash(relative), "/") {
		if component == "" || component == "." || component == ".." || strings.HasPrefix(component, ".") {
			return errors.New("unsafe output directory component")
		}
		if current == "" {
			current = component
		} else {
			current += "/" + component
		}
		if err := unix.Mkdirat(rootFD, current, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
		fd, err := openBeneath(rootFD, current, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC)
		if err != nil {
			return fmt.Errorf("unsafe output directory %q: %w", current, err)
		}
		unix.Close(fd)
	}
	return nil
}

func suffixFor(algorithm string) string {
	switch algorithm {
	case "babuk":
		return simcrypto.BabukSuffix
	case "qilin":
		return simcrypto.QilinSuffix
	default:
		return ".invalid"
	}
}

func isTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

func checkExecutionGate(euid int, terminal bool) error {
	if euid == 0 {
		if err := validateCurrentRootlessContainer(); err != nil {
			return fmt.Errorf("refusing to run the encryption simulator as root: %w", err)
		}
	}
	if !terminal {
		return errors.New("refusing encryption without an interactive TTY")
	}
	return nil
}
