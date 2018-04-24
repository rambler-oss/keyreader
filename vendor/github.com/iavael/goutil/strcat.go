package goutil

import (
	"bytes"
)

func strfmtBase(args []string) *bytes.Buffer {
	result := bytes.NewBufferString("")
	for _, arg := range args {
		result.WriteString(arg)
	}
	return result
}

// StrCat concatenates string arguments in one string
func StrCat(args ...string) string {
	result := strfmtBase(args)
	return result.String()
}

// StrCatln concatenates string arguments in one string with newline
func StrCatln(args ...string) string {
	result := strfmtBase(args)
	result.WriteRune('\n')
	return result.String()
}

// StrCatS concatenates slice of strings in one string
func StrCatS(args []string) string {
	result := strfmtBase(args)
	return result.String()
}

// StrCatSln concatenates slice of strings in one string with newline
func StrCatSln(args []string) string {
	result := strfmtBase(args)
	result.WriteRune('\n')
	return result.String()
}
