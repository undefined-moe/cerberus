# Cerberus

<center>
   <img width=256 src="./web/img/mascot-puzzle.png" alt="A smiling chibi dark-skinned anthro jackal with brown hair and tall ears looking victorious with a thumbs-up" />
</center>

Caddy plugin version of [Anubis](https://github.com/TecharoHQ/anubis/).

This plugin provides a Caddy handler that blocks unwanted requests using a sha256 PoW challenge.

While Anubis focuses on protecting websites from AI scrapers, Cerberus serves a different purpose: it's designed as a last line of defense to protect volunteer-run open source infrastructure from aggressive PCDN attacks. Different design decisions were made to achieve this goal.

## Usage

1. Install Caddy with the plugin:
   ```bash
   caddy add-package github.com/sjtug/cerberus
   ```
2. Add the handler directive to your Caddyfile. Refer to the [Caddyfile](Caddyfile) for an example configuration.

## Comparison with Anubis

- Anubis is a standalone server that can be used with any web server, while Cerberus is a Caddy plugin.
- No builtin anti-AI rules: use caddy matchers instead.
- Can be set up to block IP subnets if there are too many failed challenge attempts to prevent abuse.
- ~~No custom UI or anime girls.~~ Now with an AI-generated placeholder mascot lol

## Configuration

Check [Caddyfile](Caddyfile) for an example configuration.

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