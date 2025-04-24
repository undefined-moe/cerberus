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

*WARNING*: Each cerberus directive will create a new instance of the handler. This means that if you have multiple cerberus directives, each one will have its own internal state and consume memory. Please use the `cerberus` directive only once per site.

## Development

If you modified any web asset, you need to run the following command to build the dist files:
```bash
$ devenv tasks run dist:build
```

Please run tests and lints before submitting a PR:
```bash
$ direnv test # or go test
$ golangci-lint run
```