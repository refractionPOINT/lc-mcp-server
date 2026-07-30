package forensics

import "testing"

// The expectations below were validated against the real tokenizer
// (github.com/refractionPOINT/shlex, the fork legion_tasking-go uses):
// splitting each want string reproduces the original values.
func TestBuildCommandStringQuotesValues(t *testing.T) {
	cases := []struct {
		name       string
		command    string
		positional []string
		flags      map[string]interface{}
		want       string
	}{
		{
			name:    "no arguments",
			command: "os_packages",
			want:    "os_packages",
		},
		{
			name:    "flags are sorted and quoted",
			command: "mem_strings",
			flags:   map[string]interface{}{"pid": 42, "depth": 3},
			want:    "mem_strings --depth '3' --pid '42'",
		},
		{
			name:       "windows path keeps single backslashes and survives spaces",
			command:    "dir_list",
			positional: []string{`C:\Program Files`, "*.exe"},
			flags:      map[string]interface{}{"depth": 1},
			want:       `dir_list 'C:\Program Files' '*.exe' --depth '1'`,
		},
		{
			name:       "registry path is not backslash-doubled",
			command:    "reg_list",
			positional: []string{`hklm\software\microsoft`},
			want:       `reg_list 'hklm\software\microsoft'`,
		},
		{
			name:       "yara rule body with braces, quotes and spaces stays one token",
			command:    "yara_scan",
			positional: []string{`rule evil { strings: $a = "bad" condition: $a }`},
			flags:      map[string]interface{}{"pid": 4},
			want:       `yara_scan 'rule evil { strings: $a = "bad" condition: $a }' --pid '4'`,
		},
		{
			name:       "embedded single quote is closed, double-quoted and reopened",
			command:    "reg_list",
			positional: []string{`it's`},
			want:       `reg_list 'it'"'"'s'`,
		},
		{
			name:    "string slice repeats the flag once per value",
			command: "mem_find_string",
			flags:   map[string]interface{}{"string": []string{"evil", "two words"}},
			want:    "mem_find_string --string 'evil' --string 'two words'",
		},
		{
			name:    "empty string slice emits nothing",
			command: "mem_find_string",
			flags:   map[string]interface{}{"string": []string{}, "pid": 7},
			want:    "mem_find_string --pid '7'",
		},
		{
			name:       "a value that looks like a flag stays a positional token",
			command:    "reg_list",
			positional: []string{"--pid"},
			want:       "reg_list '--pid'",
		},
		{
			name:       "empty value is preserved as an empty token",
			command:    "reg_list",
			positional: []string{""},
			want:       "reg_list ''",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildCommandString(tc.command, tc.positional, tc.flags)
			if got != tc.want {
				t.Errorf("buildCommandString() =\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
}
