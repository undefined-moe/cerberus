package web

import "encoding/json"

type Asset struct {
	File string `json:"file"`
}

type Manifest map[string]Asset

func LoadManifest() (Manifest, error) {
	rawAssets, err := Content.ReadFile("dist/.vite/manifest.json")
	if err != nil {
		return nil, err
	}

	var manifest Manifest
	err = json.Unmarshal(rawAssets, &manifest)
	if err != nil {
		return nil, err
	}

	return manifest, nil
}
