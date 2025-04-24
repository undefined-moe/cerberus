#!/usr/bin/env bash

# TODO
./tailwindcss -i ./web/global.css -o ./web/dist/global.css --minify
pnpx esbuild ./web/js/main.mjs --bundle --minify --outfile=./web/dist/main.mjs --allow-overwrite

rm -rf ./web/dist/img
cp -r ./web/img ./web/dist/img
pngquant -f --ext .png ./web/dist/img/*.png

go tool templ generate