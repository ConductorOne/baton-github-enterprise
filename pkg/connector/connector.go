package connector

import (
	"context"

	cfg "github.com/conductorone/baton-github-enterprise/pkg/config"
	githubCfg "github.com/conductorone/baton-github/pkg/config"
	"github.com/conductorone/baton-github/pkg/connector"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
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
		DirectCollaboratorsOnly:  ghc.DirectCollaboratorsOnly,
	}, cliOpts)
}

func DefaultCapabilitiesBuilder() connectorbuilder.ConnectorBuilderV2 {
	return &defaultCapabilitiesBuilder{}
}

type defaultCapabilitiesBuilder struct{}

func (d *defaultCapabilitiesBuilder) Metadata(_ context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{DisplayName: "GitHub Enterprise"}, nil
}

func (d *defaultCapabilitiesBuilder) Validate(_ context.Context) (annotations.Annotations, error) {
	return nil, nil
}

func (d *defaultCapabilitiesBuilder) ResourceSyncers(_ context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		connector.OrgBuilder(nil, nil, nil, nil, false),
		connector.TeamBuilder(nil, nil, false),
		connector.UserBuilder(nil, nil, nil, nil, nil, nil),
		connector.RepositoryBuilder(nil, nil, false, false),
		connector.OrgRoleBuilder(nil, nil),
		connector.InvitationBuilder(connector.InvitationBuilderParams{}),
		connector.APITokenBuilder(nil, nil),
		connector.EnterpriseRoleBuilder(nil, nil, nil, nil),
		connector.LicenseBuilder(nil, nil),
		connector.AppBuilder(nil, nil),
	}
}
