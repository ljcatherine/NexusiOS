package main

// This fixed helper never executes project code, shell commands or Git. The
// parent launches it only inside a namespace with a single managed writable root.
import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
	"time"
)

// Empty in production. Fault-injection builds may set this through the Go
// linker; no environment, HTTP field or helper input can select a crash point.
var patchHelperCrashPoint string

func patchHelperCrashAt(point string) {
	if patchHelperCrashPoint == point {
		os.Exit(97)
	}
}

type patchStageIdentity struct {
	Name            string `json:"name"`
	Device          uint64 `json:"device"`
	Inode           uint64 `json:"inode"`
	ParentDevice    uint64 `json:"parent_device"`
	ParentInode     uint64 `json:"parent_inode"`
	OriginalDevice  uint64 `json:"original_device"`
	OriginalInode   uint64 `json:"original_inode"`
	OriginalVersion string `json:"original_version"`
}

func (s patchStageIdentity) valid(operation string) bool {
	return hex32.MatchString(operation) && s.Name == ".nexus-patch-"+operation+".tmp" &&
		s.Device != 0 && s.Inode != 0 && s.ParentDevice == s.Device && s.ParentInode != 0 &&
		s.OriginalDevice == s.Device && s.OriginalInode != 0 && hex64.MatchString(s.OriginalVersion)
}

type patchHelperRequest struct {
	Request patchRequest        `json:"request"`
	Root    patchRootAnchor     `json:"root"`
	Recover *patchStageIdentity `json:"recover,omitempty"`
}
type patchHelperReply struct {
	Phase  string              `json:"phase"`
	Stage  *patchStageIdentity `json:"stage,omitempty"`
	SHA256 string              `json:"sha256,omitempty"`
}

// init also supports the Go test executable as a reexec fixture. No listener is
// opened in helper mode. Its input is the parent's fixed, bounded private pipe.
func init() {
	if len(os.Args) != 2 || os.Args[1] != "--nexus-patch-helper-v1" {
		return
	}
	code := 0
	if err := runPatchHelper(os.Stdin, os.Stdout); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(patchHelperReply{Phase: "uncertain"})
		code = 2
	}
	os.Exit(code)
}

func patchParent(root *workspace, relative string) (*os.File, string, error) {
	parts, err := segments(relative, false)
	if err != nil || !validPatchPath(relative) {
		return nil, "", errForbidden
	}
	parent, err := root.openDir(parts[:len(parts)-1])
	if err != nil {
		return nil, "", err
	}
	var a, b syscall.Stat_t
	rm, e1 := descriptorMountID(root.fd)
	pm, e2 := descriptorMountID(int(parent.Fd()))
	if e1 != nil || e2 != nil || rm != pm || privateOwned(int(parent.Fd()), true) != nil ||
		syscall.Fstat(root.fd, &a) != nil || syscall.Fstat(int(parent.Fd()), &b) != nil || a.Dev != b.Dev {
		parent.Close()
		return nil, "", errForbidden
	}
	return parent, parts[len(parts)-1], nil
}

func openStage(parent *os.File, stage patchStageIdentity) (*os.File, error) {
	fd, err := syscall.Openat(int(parent.Fd()), stage.Name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "patch-stage")
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || uint64(st.Dev) != stage.Device || st.Ino != stage.Inode || privateOwned(fd, false) != nil {
		f.Close()
		return nil, errPatchUncertain
	}
	return f, nil
}

func checkStageText(f *os.File, expected string) error {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxReadBytes+1))
	if err != nil || len(data) > maxReadBytes || hashText(string(data)) != expected {
		return errPatchUncertain
	}
	return nil
}

func runPatchHelper(input io.Reader, output io.Writer) error {
	decoder := json.NewDecoder(io.LimitReader(input, (512<<10)+4096))
	decoder.DisallowUnknownFields()
	var request patchHelperRequest
	if decoder.Decode(&request) != nil || request.Request.validate() != nil {
		return errPatchBinding
	}
	p := request.Request
	fd, err := openConfiguredRoot("/workspace")
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	root := &workspace{fd: fd}
	var rootStat syscall.Stat_t
	if syscall.Fstat(fd, &rootStat) != nil || uint64(rootStat.Dev) != request.Root.Device || rootStat.Ino != request.Root.Inode || privateOwned(fd, true) != nil {
		return errForbidden
	}
	parent, name, err := patchParent(root, p.Path)
	if err != nil {
		return err
	}
	defer parent.Close()
	var parentStat syscall.Stat_t
	if syscall.Fstat(int(parent.Fd()), &parentStat) != nil {
		return errForbidden
	}
	encoder := json.NewEncoder(output)
	reply := func(phase string, stage *patchStageIdentity, sha string) error {
		return encoder.Encode(patchHelperReply{phase, stage, sha})
	}
	if request.Recover != nil {
		stage := *request.Recover
		if !stage.valid(p.OperationID) || stage.ParentDevice != uint64(parentStat.Dev) || stage.ParentInode != parentStat.Ino {
			return errPatchUncertain
		}
		target, inspectErr := root.inspectPatchFile(p.Path)
		if inspectErr != nil {
			return errPatchUncertain
		}
		if target.Device == stage.Device && target.Inode == stage.Inode && target.SHA256 == p.ReplacementSHA256 {
			// A stage and installed target cannot both exist for a single-link inode.
			if f, e := openStage(parent, stage); e == nil {
				f.Close()
				return errPatchUncertain
			} else if !errors.Is(e, syscall.ENOENT) {
				return errPatchUncertain
			}
			if parent.Sync() != nil {
				return errPatchUncertain
			}
			return reply("applied", &stage, p.ReplacementSHA256)
		}
		if target.Device != stage.OriginalDevice || target.Inode != stage.OriginalInode || target.Version != stage.OriginalVersion || target.SHA256 != p.BaseSHA256 {
			return errPatchUncertain
		}
		f, e := openStage(parent, stage)
		if e != nil {
			return errPatchUncertain
		}
		if e = checkStageText(f, p.ReplacementSHA256); e != nil {
			f.Close()
			return e
		}
		f.Close()
		// A durable known stage still exists and the exact original is installed:
		// this operation did not rename. Refuse replay; clean only that private stage.
		if syscall.Unlinkat(int(parent.Fd()), stage.Name) != nil || parent.Sync() != nil {
			return errPatchUncertain
		}
		return reply("failed", &stage, "")
	}
	if p.ExpiresAt <= time.Now().Unix() {
		return reply("conflict", nil, "")
	}
	original, err := root.inspectPatchFile(p.Path)
	if err != nil || original.SHA256 != p.BaseSHA256 {
		return reply("conflict", nil, "")
	}
	stage := patchStageIdentity{Name: ".nexus-patch-" + p.OperationID + ".tmp", ParentDevice: uint64(parentStat.Dev), ParentInode: parentStat.Ino,
		OriginalDevice: original.Device, OriginalInode: original.Inode, OriginalVersion: original.Version}
	n, err := syscall.Openat(int(parent.Fd()), stage.Name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errPatchUncertain
	}
	f := os.NewFile(uintptr(n), "patch-stage")
	if count, e := io.WriteString(f, p.Replacement); e != nil || count != len(p.Replacement) {
		f.Close()
		return errPatchUncertain
	}
	patchHelperCrashAt("before_stage_sync")
	if f.Sync() != nil {
		f.Close()
		return errPatchUncertain
	}
	var st syscall.Stat_t
	if syscall.Fstat(n, &st) != nil || privateOwned(n, false) != nil {
		f.Close()
		return errPatchUncertain
	}
	f.Close()
	stage.Device = uint64(st.Dev)
	stage.Inode = st.Ino
	if !stage.valid(p.OperationID) || parent.Sync() != nil {
		return errPatchUncertain
	}
	patchHelperCrashAt("before_stage_reply")
	if err := reply("staged", &stage, ""); err != nil {
		return err
	}
	// The parent journals the identity and checks current authorization before
	// sending this distinct permit. EOF/cancel before it cannot mutate the target.
	var permit struct {
		Commit bool `json:"commit"`
	}
	if decoder.Decode(&permit) != nil || !permit.Commit {
		return nil
	}
	if p.ExpiresAt <= time.Now().Unix() {
		return reply("conflict", &stage, "")
	}
	current, err := root.inspectPatchFile(p.Path)
	if err != nil || current.Device != stage.OriginalDevice || current.Inode != stage.OriginalInode || current.Version != stage.OriginalVersion || current.SHA256 != p.BaseSHA256 {
		return reply("conflict", &stage, "")
	}
	sf, err := openStage(parent, stage)
	if err != nil {
		return err
	}
	if err = checkStageText(sf, p.ReplacementSHA256); err != nil {
		sf.Close()
		return err
	}
	sf.Close()
	// No unmanaged writers are allowed in this private service-owned workspace.
	// Linux rename is atomic replacement, not CAS against a competing OS owner.
	patchHelperCrashAt("before_rename")
	if syscall.Renameat(int(parent.Fd()), stage.Name, int(parent.Fd()), name) != nil {
		return errPatchUncertain
	}
	patchHelperCrashAt("after_rename")
	if parent.Sync() != nil {
		return errPatchUncertain
	}
	patchHelperCrashAt("after_parent_sync")
	return reply("applied", &stage, p.ReplacementSHA256)
}
