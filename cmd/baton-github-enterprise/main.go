package main

import (
	"context"

	cfg "github.com/conductorone/baton-github-enterprise/pkg/config"
	githubConnector "github.com/conductorone/baton-github/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"

	"github.com/conductorone/baton-github-enterprise/pkg/connector"
)

var version = "dev"

func main() {
	ctx := context.Background()
	config.RunConnector(ctx,
		"baton-github-enterprise",
		version,
		cfg.Config,
		connector.NewLambdaConnector,
		connectorrunner.WithSessionStoreEnabled(),
		connectorrunner.WithDefaultCapabilitiesConnectorBuilderV2(&githubConnector.GitHub{}),
	)
}
