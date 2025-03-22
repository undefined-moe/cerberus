# Cerberus

Caddy plugin version of [Anubis](https://github.com/TecharoHQ/anubis/).

This plugin provides a Caddy handler that blocks unwanted requests using a sha256 PoW challenge.
It's not a full replacement for Anubis, but most of the features are there.

## Usage

1. Install Caddy with the plugin:
   ```bash
   caddy add-package github.com/sjtug/cerberus
   ```
2. Add the handler directive to your Caddyfile. Refer to the [Caddyfile](Caddyfile) for an example configuration.

## Comparison with Anubis

- Anubis is a standalone server that can be used with any web server, while Cerberus is a Caddy plugin.
- No support for custom rules: use caddy matchers instead.
- No custom UI or anime girls.
- Scripts and parameters are inlined in HTML.
- No separate endpoint for challenge response: any query with `?cerberus` will be treated as a challenge response.

## Configuration

Check [Caddyfile](Caddyfile) for an example configuration.

## Development

If you modified the js file, you need to run the following command to rebundle the js file:
```bash
$ devenv tasks js:bundle
```

Also, you need to run the following command to recompile the template if modified:
```bash
$ devenv tasks go:codegen
```

Please run the linter before submitting a PR:
```bash
$ golangci-lint run
```