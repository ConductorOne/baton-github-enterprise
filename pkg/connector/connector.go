package connector

import (
	"context"

	cfg "github.com/conductorone/baton-github-enterprise/pkg/config"
	githubCfg "github.com/conductorone/baton-github/pkg/config"
	"github.com/conductorone/baton-github/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
)

func NewLambdaConnector(ctx context.Context, ghc *cfg.Githubenterprise, cliOpts *cli.ConnectorOpts) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	return connector.NewLambdaConnector(ctx, &githubCfg.Github{
		Token:                    ghc.Token,
		Orgs:                     ghc.Orgs,
		Enterprises:              ghc.Enterprises,
		InstanceUrl:              ghc.InstanceUrl,
		SyncSecrets:              ghc.SyncSecrets,
		OmitArchivedRepositories: ghc.OmitArchivedRepositories,
		AppId:                    ghc.AppId,
		AppPrivatekeyPath:        ghc.AppPrivatekeyPath,
		Org:                      ghc.Org,
	}, cliOpts)
}
