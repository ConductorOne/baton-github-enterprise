package main

import (
	cfg "github.com/conductorone/baton-github-enterprise/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("github", cfg.Config)
}
