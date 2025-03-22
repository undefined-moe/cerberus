{ pkgs, lib, config, inputs, ... }:

let
  pkgs-unstable = import inputs.nixpkgs-unstable { system = pkgs.stdenv.system; };
in
{
  # https://devenv.sh/packages/
  packages = with pkgs-unstable; [ git xcaddy templ esbuild golangci-lint ];

  # https://devenv.sh/languages/
  languages.go = {
    enable = true;
    package = pkgs-unstable.go;
    enableHardeningWorkaround = true;
  };

  tasks = {
    "js:bundle".exec = "esbuild js/main.mjs --bundle --minify --outfile=dist/main.js --allow-overwrite";
    "go:codegen".exec = "templ generate";
  };

  # tasks = {
  #   "myproj:setup".exec = "mytool build";
  #   "devenv:enterShell".after = [ "myproj:setup" ];
  # };

  # https://devenv.sh/tests/
  enterTest = ''
    echo "Running tests"
    git --version | grep --color=auto "${pkgs.git.version}"
  '';

  # https://devenv.sh/git-hooks/
  # git-hooks.hooks.shellcheck.enable = true;

  # See full reference at https://devenv.sh/reference/options/
}
