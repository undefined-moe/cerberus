package core

const (
	AppName = "cerberus"
	VarName = "cerberus-block"
	Version = "v0.1.3"
)

type Instance struct {
	*InstanceState
	Config
}
