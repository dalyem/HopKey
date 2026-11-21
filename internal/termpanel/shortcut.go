package termpanel

// Shortcut is one entry in the session panel.
type Shortcut struct {
	Keys    string // one or two printable ASCII characters
	Name    string // display name, already safe for the terminal
	Command string // one line, no control characters, at most 4096 bytes
	Enter   bool   // press Enter after typing Command
	Host    bool   // true: a host shortcut, false: global
}
