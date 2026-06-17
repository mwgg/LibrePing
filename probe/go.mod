module github.com/mwgg/libreping/probe

go 1.26

require github.com/mwgg/libreping/pkg v0.0.0

require (
	golang.org/x/net v0.28.0
	golang.org/x/sys v0.24.0 // indirect
)

replace github.com/mwgg/libreping/pkg => ../pkg
