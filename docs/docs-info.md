# GitHub Enterprise Connector Setup Guide

This connector is a wrapper. `NewLambdaConnector` copies its config onto `baton-github` and returns that connector. Resource sync, grants, and provisioning are implemented there. This file records what is different because the instance is a custom domain and because this repo publishes the enterprise types.

Behavior of each resource is in [baton-github `docs/docs-info.md`](https://github.com/ConductorOne/baton-github/blob/main/docs/docs-info.md). Do not fork that description here.

---

## Requirements

- A GitHub instance at a custom domain: GitHub Enterprise Cloud with data residency (`*.ghe.com`) or GitHub Enterprise Server
- Either a **personal access token (classic)** or a **GitHub App**
- For the built-in Enterprise Owner role: a GitHub App installed on **both** the enterprise account and the organization, with **Enterprise people** read and write. That role is GitHub Enterprise Cloud only

---

## Connector capabilities

1. **What resources does the connector sync?**
   The same resources as `baton-github`:
   - Organizations
   - Users
   - Invitations
   - Teams
   - Repositories
   - Organization roles
   - Enterprise roles, only when `--enterprises` is set
   - Licenses, only when `--enterprises` is set
   - GitHub Apps installed on the organization
   - API keys, only when `--sync-secrets` is set
   - A usage app and an audit-log usage feed, only when `--sync-last-activity` is set

2. **Can the connector provision any resources? If so, which ones?**
   The same operations as `baton-github`, including Grant and Revoke of the built-in Enterprise **Owner** role. A personal access token advertises that capability and the request fails naming the GitHub App. See [Enterprise Owner provisioning](#enterprise-owner-provisioning).

3. **Does the connector emit any event feeds?**
   Yes, when `--sync-last-activity` is set. The flag is a normal config field on this connector. On `baton-github` it is hidden, because audit-log access is an enterprise concern and this connector is the one that sets it.

4. **Does the connector support grant expansion?**
   Yes, the same three expansions as `baton-github`: baseline repository permission through the organization, an organization role assigned to a team, and an enterprise license through the role's `assigned` entitlement.

---

## Connector credentials

1. **What credentials or information are needed to set up the connector?**

   **Personal access token (classic)**

   **Args**:
   `--token` — the GitHub personal access token
   `--instance-url` — required, the instance URL
   `--orgs` — optional, limits syncing to specific organizations

   **GitHub App**

   **Args**:
   `--app-id` — the GitHub App ID
   `--app-privatekey-path` — path to the App's private key `.pem`
   `--org` — required, the single organization the App is installed on
   `--instance-url` — required, the instance URL

   Common to both:
   `--enterprises` — enterprises to sync enterprise roles and licenses for. A personal access token syncs every role. A GitHub App syncs and provisions the built-in Owner role, and the App must be installed on the enterprise account as well as the organization
   `--sync-secrets` — GitHub App only. Sync fine-grained personal access tokens as API keys
   `--sync-last-activity` — emit the audit-log usage event feed
   `--omit-archived-repositories` — skip archived repositories
   `--direct-collaborators-only` — reduce API calls on large organizations

2. **How does a user create or look up that credential?**
   The customer steps are in `docs/connector.mdx`. The enterprise installation is a second install of the same App: an enterprise owner opens the App's installation page and selects the enterprise. That installation does not grant organization or repository access, so both are required. See [Installing a GitHub App on your enterprise](https://docs.github.com/en/enterprise-cloud@latest/apps/using-github-apps/installing-a-github-app-on-your-enterprise).

---

## Resource Details

Each type below is built by `baton-github`. The IDs match `baton_capabilities.json` in this repo.

### Organizations

- **Resource type ID**: `org`
- **Provisioning**: Grant and Revoke of organization membership

### Users

- **Resource type ID**: `user`
- **Provisioning**: `Delete` removes the user from the organization

### Invitations

- **Resource type ID**: `invitation`
- **Provisioning**: `CreateAccount` sends an organization invitation; `Delete` cancels it

### Teams

- **Resource type ID**: `team`
- **Provisioning**: Grant and Revoke of team membership

### Repositories

- **Resource type ID**: `repository`
- **Provisioning**: Grant and Revoke of repository access

### Organization roles

- **Resource type ID**: `org_role`
- **Provisioning**: Grant and Revoke of the role assignment

### Enterprise roles

- **Resource type ID**: `enterprise_role`
- **Description**: Synced only when `--enterprises` is set. A personal access token reads every role from consumed-licenses. A GitHub App reads the built-in Owner role, plus pending Owner invitations, and can grant and revoke that role
- **Entitlements**: `assigned`
- **Provisioning**: Advertised in this connector's published capabilities. Only Owner provisioning succeeds, and only with a GitHub App. See [Enterprise Owner provisioning](#enterprise-owner-provisioning)

### Licenses

- **Resource type ID**: `license`
- **Description**: Enterprise seat consumption, only when `--enterprises` is set
- **Limitation**: Personal access token only. A GitHub App gets 403 from consumed-licenses. The type is opt-in. On a GitHub App deployment that sets `--enterprises`, leave it disabled or the sync fails

### GitHub Apps

- **Resource type ID**: `app`
- **Provisioning**: None

### API keys

- **Resource type ID**: `api-key`
- **Provisioning**: None. Synced only when `--sync-secrets` is set

---

## Enterprise Owner provisioning

The mutations and the read path are `baton-github`'s. What this repo adds is who publishes the capability, and what a custom domain does to it.

`pkg/connector/connector.go` registers `EnterpriseRoleProvisioningBuilder` in `defaultCapabilitiesBuilder`. `baton-github`'s `DefaultCapabilitiesBuilder` omits `enterprise_role` and `license`, because that catalog describes a `github.com` account without an enterprise. Delegating to it would drop both types from this connector the moment the dependency is bumped. The provisioning builder is the one the running connector registers when `--enterprises` is set. The read-only `EnterpriseRoleBuilder` does not implement Grant and Revoke, so registering it here would publish sync only.

There is no separate flag. `--enterprises` turns the role on. Both credentials get the provisioning builder. A personal access token fails Grant and Revoke with an error that names the GitHub App.

Grant invites the user (`inviteEnterpriseAdmin`). GitHub assigns Owner when they accept, and the grant ID does not change. A pending invitation and an accepted Owner are the same grant. If the user already holds an administrator role, such as billing manager, GitHub rejects the invite and the connector returns `FailedPrecondition` instead of promoting them. The prior role cannot be read back, so Revoke could not restore it.

Revoke demotes an accepted Owner to `UNAFFILIATED`, which keeps enterprise membership, and cancels a pending invitation. `NOT_FOUND` on either mutation is success.

### GitHub Enterprise Server is not Cloud

`isEnterpriseCloud` treats `github.com`, `ghe.com`, and `*.ghe.com` as Enterprise Cloud. Any other host is GitHub Enterprise Server. With `--enterprises` set, a Server host fails the sync before the enterprise API is called. The error says the capability is Cloud-only and to remove `--enterprises`.

Server has `addEnterpriseAdmin` and `removeEnterpriseAdmin`. It does not have `inviteEnterpriseAdmin`, `updateEnterpriseAdministratorRole`, or `cancelEnterpriseAdminInvitation`. That path is not implemented.

`GET /enterprises/{enterprise}/consumed-licenses` is also absent on Server, for either credential. The license type still reaches that call on the token path and gets a 404. The host check above covers the enterprise role, not this license call.

### A setup problem skips the role; anything else fails the sync

On Cloud, a setup problem (the App is not installed on the enterprise, or the organization does not belong to it) completes the sync and leaves that enterprise out. Several configured slugs are skipped one by one, and an enterprise whose client built is kept. An organization belongs to one enterprise, so under App auth at most one slug succeeds. The skipped slug is tried again on the next sync.

A rate limit, a 5xx, or a cancelled context fails the sync. Grant and Revoke still return the error.

The trade-off: a deployment that was syncing Owner and then loses the enterprise installation completes one sync with that enterprise missing. C1 drops the Owner role and its grants until the installation is restored, and a time-bound grant that expires in that window has nothing left to revoke. Failing the sync instead would turn an App deployment that never installed on the enterprise into a red sync. Server is not part of this skip. It fails closed.

### Pending invitations

C1 has no pending state, so an invitation and an accepted Owner look the same. Time-bound access starts when the invitation is sent, not when it is accepted. GitHub expires a pending invitation after seven days. The sync can only see invitations for users who are already enterprise members. Grant rejects a principal who is not a member.

### Published capabilities

`baton_capabilities.json` is what C1 stamps when the connector is created. This repo's file includes `enterprise_role` with `CAPABILITY_SYNC` and `CAPABILITY_PROVISION`, and `license` with `CAPABILITY_SYNC`. A customer still has to select those types when selective sync is on. The type is off until selected, not unreachable.

Regenerate after a resource-type or config-field change with `./baton-github-enterprise capabilities` and `./baton-github-enterprise config`, without credentials. On a push to `main`, `.github/workflows/generate-baton-metadata.yaml` regenerates both and commits them. Pull requests only check that the committed files match the binary.

---

## Authentication

Same two methods as `baton-github`. A GitHub App that provisions Owner holds two installation tokens: one for the organization, which reads `Organization.enterpriseOwners`, and one for the enterprise account, which runs the administrator mutations.

---

## API Endpoints Used

Owned by `baton-github`. The calls this connector's enterprise path depends on:

**REST**

- `GET /enterprises/{enterprise}/installation` — the App's installation on the enterprise. A 404 is treated as a setup problem
- `GET /enterprises/{enterprise}/consumed-licenses` — enterprise roles on the token path, and licenses. PAT only. Absent on GitHub Enterprise Server

**GraphQL**

- `organization(login:) { enterpriseOwners }` — Owner role grants, organization installation token
- `enterpriseAdministratorInvitation` — a pending Owner invitation for one login
- `inviteEnterpriseAdmin`, `updateEnterpriseAdministratorRole`, `cancelEnterpriseAdminInvitation` — Owner Grant and Revoke. Cloud only

---

## Pagination

Same as `baton-github`. Consumed-licenses is 1-indexed. GraphQL connections use cursor pagination, 100 per page.

---

## Rate Limits

Same as `baton-github`. The connector returns GitHub's rate limit headers to the SDK. A rate limit while building an enterprise client fails the sync. It is not a setup problem.

---

## API Documentation

- **REST**: https://docs.github.com/en/rest
- **GraphQL**: https://docs.github.com/en/graphql
- **Installing a GitHub App on your enterprise**: https://docs.github.com/en/enterprise-cloud@latest/apps/using-github-apps/installing-a-github-app-on-your-enterprise
- **Inviting people to manage your enterprise**: https://docs.github.com/en/enterprise-cloud@latest/admin/managing-accounts-and-repositories/managing-users-in-your-enterprise/inviting-people-to-manage-your-enterprise
- **Enterprise licensing**: https://docs.github.com/en/enterprise-cloud@latest/rest/enterprise-admin/license
- **baton-github internal notes**: https://github.com/ConductorOne/baton-github/blob/main/docs/docs-info.md
