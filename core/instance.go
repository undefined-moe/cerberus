package core

const (
	AppName = "cerberus"
	VarName = "cerberus-block"
)

type Instance struct {
	*InstanceState
	Config
}
