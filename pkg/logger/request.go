package logger

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/utils"
)

const (
	UnknownValue = "unknown"
)

type RequestType string

const (
	DNSRequestType    RequestType = "dns"
	HTTPRequestType   RequestType = "http"
	PacketRequestType RequestType = "packet"
)

func (bt RequestType) String() string {
	return string(bt)
}

type RequestExplanation string

const (
	NotInAllowListExplanation RequestExplanation = "NotInAllowList"
	InBlockListedExplaination RequestExplanation = "MatchedBlockListDomain"
	PacketIPNotInAllowList    RequestExplanation = "IPNotAllowed"
	PacketIPv6Blocked         RequestExplanation = "IPv6AlwaysBlocked"
	AllowedExplaination       RequestExplanation = "Allowed"
)

func (e RequestExplanation) String() string {
	return string(e)
}

var pid2CmdLineCache *utils.GenericSyncMap[int, string] = new(utils.GenericSyncMap[int, string])

func CmdLineFromPid(pid int) string {
	cmdRun := "unknown"

	if pid == -1 {
		return "unknown, pid is -1"
	}

	if pid == 0 {
		return "root process (pid 0)"
	}

	// Lookup the processPath for the event
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	cmdlineBytes, err := os.ReadFile(cmdlinePath)
	if err == nil {
		// cmdline args are null-terminated, replace nulls with spaces
		cmdline := string(bytes.ReplaceAll(cmdlineBytes, []byte{0}, []byte{' '}))
		pid2CmdLineCache.Store(pid, cmdline)
		cmdRun = cmdline
	} else {
		slog.Error("reading cmdline", SlogError(err))
	}
	return cmdRun
}

type RequestLog struct {
	Because    RequestExplanation
	Blocked    bool
	BlockedAt  RequestType
	Domains    string
	RuleSource models.RuleSource
	PID        int
	IP         string
	OriginalIP string
	URL        string
	Port       string
}

func LogRequest(r *RequestLog) {
	// Convert struct to slog attributes
	content := []interface{}{
		slog.String("because", string(r.Because)),
		slog.Bool("blocked", r.Blocked),
		slog.String("blockedAt", string(r.BlockedAt)),
		slog.String("domains", r.Domains),
		slog.String("ruleSource", string(r.RuleSource.KindHumanReadable())),
		slog.String("ruleSourceComment", r.RuleSource.Comment),
		slog.Int("pid", r.PID),
		slog.String("port", r.Port),
		slog.String("ip", r.IP),
		slog.String("originalIp", r.OriginalIP),
		slog.String("url", r.URL),
		slog.String("cmd", CmdLineFromPid(r.PID)),
	}

	msg := fmt.Sprintf("%s BLOCKED", strings.ToUpper(r.BlockedAt.String()))

	if r.Blocked {
		slog.Warn(msg, content...)
	} else {
		slog.Info(msg, content...)
	}
}
