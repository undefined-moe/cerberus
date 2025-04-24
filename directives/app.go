package directives

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/sjtug/cerberus/core"
	"go.uber.org/zap"
)

// App is the global configuration for a cerberus instance.
type App struct {
	// Unique instance ID. You need to refer to the same instance ID in both the middleware and the handler directives.
	InstanceID string
	core.Config
}

func (c *App) Provision(context caddy.Context) error {
	c.Config.Provision()

	context.Logger().Debug("cerberus instance provision", zap.String("instance_id", c.InstanceID))

	core.Instances.Lock()
	defer core.Instances.Unlock()

	// If the instance already exists and the config is compatible, update the config.
	existing, ok := core.Instances.Pool[c.InstanceID]
	if ok && existing.Config.StateCompatible(&c.Config) {
		context.Logger().Info("cerberus instance config updated without state reset", zap.String("instance_id", c.InstanceID))
		existing.Config = c.Config
		return nil
	}

	state, pendingElems, blocklistElems, err := core.NewInstanceState(c.MaxMemUsage, c.MaxMemUsage)
	if err != nil {
		return err
	}
	context.Logger().Info("cerberus cache initialized",
		zap.Int64("max_pending", pendingElems),
		zap.Int64("max_blocklist", blocklistElems),
	)

	instance := &core.Instance{
		Config:        c.Config,
		InstanceState: state,
	}
	if _, ok := core.Instances.Pool[c.InstanceID]; ok {
		context.Logger().Info("existing cerberus instance with incompatible config found, resetting state", zap.String("instance_id", c.InstanceID))
	}
	core.Instances.Pool[c.InstanceID] = instance

	return nil
}

func (c *App) Validate() error {
	return c.Config.Validate()
}

func (c *App) Start() error {
	return nil
}

func (c *App) Stop() error {
	return nil
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "cerberus",
		New: func() caddy.Module { return new(App) },
	}
}

var (
	_ caddy.App         = (*App)(nil)
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.Validator   = (*App)(nil)
)
