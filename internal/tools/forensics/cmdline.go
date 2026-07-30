package forensics

import (
	"fmt"
	"sort"
	"strings"
)

// The platform tokenizes a sensor task string with github.com/refractionPOINT/shlex
// (legion_tasking-go/service/command_parser/service.go, ParseCommand) before handing
// the tokens to go-arg. Any interpolated value carrying a space, quote or backslash
// therefore has to be quoted or it splits into extra tokens (or is read as a flag).
//
// That fork of shlex is not POSIX: outside quotes a backslash is emitted literally
// *and* the rune after it is taken literally, so the usual '\'' trick for an
// embedded single quote leaks a backslash into the value. Single quotes are
// non-escaping (everything up to the next ' is literal, backslashes included), and
// double quotes are escaping, so the portable form is to close the single-quoted
// run, emit the quote inside double quotes, and reopen: 'it'"'"'s'.

// quoteCommandValue renders v as a single shlex token.
func quoteCommandValue(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'"'"'`) + "'"
}

// buildCommandString assembles a sensor task string: the command name, then the
// positional arguments in order, then the flags sorted by name. Every value is
// quoted; flag names are not (they are literals we control).
//
// A []string flag value emits the flag once per element, which is what the
// command parser's `separate` flags require (e.g. mem_find_string's --string).
// A nil or empty []string emits nothing.
func buildCommandString(command string, positionalArgs []string, flagParams map[string]interface{}) string {
	var b strings.Builder
	b.WriteString(command)

	for _, arg := range positionalArgs {
		b.WriteString(" ")
		b.WriteString(quoteCommandValue(arg))
	}

	names := make([]string, 0, len(flagParams))
	for k := range flagParams {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, k := range names {
		if values, ok := flagParams[k].([]string); ok {
			for _, v := range values {
				b.WriteString(fmt.Sprintf(" --%s %s", k, quoteCommandValue(v)))
			}
			continue
		}
		b.WriteString(fmt.Sprintf(" --%s %s", k, quoteCommandValue(fmt.Sprintf("%v", flagParams[k]))))
	}

	return b.String()
}
