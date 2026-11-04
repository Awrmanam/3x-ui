# Multi-admin / reseller isolation — architecture and rollout gate

**Status:** design plus standalone policy engine. This PR does NOT expose accounts, change the DB schema, or activate new administrator login. Production and main remain unchanged. **Do not enable subordinate accounts before all resource access is enforced.**

## Requirements
- Existing 3x-ui login supports owner, sudo, admin, reseller and owner-defined custom role presets.
- Owner has immutable authority over staff accounts, granular module/action grants, assigned inbounds, quotas, session revocation, and per-admin subscription branding.
- Resellers can create clients on assigned shared inbounds without seeing each other's client credentials, stats, subscriptions or bulk operations.
- Subscription title, support username/link, remark template, share-link template, subscription-page template, and trusted domain must resolve from the *client's owner*, not whichever operator is browsing.
- All changes should be testable for SQLite and PostgreSQL and upgrade without changing legacy users' IDs/links/traffic.

## Security invariants
1. Resolve principal, role and overrides from authenticated, current database records; never accept trusted user IDs, role or assignment from request payloads. Deny inactive principals.
2. Enforce every action at HTTP/API boundaries **and** ownership on the actual SQL query/mutation. Filtering navigation menus is insufficient.
3. An inbound assignment grants use, not ownership; even when sharing a physical inbound, one reseller must not see embedded `settings.clients` or `ClientStats` of another.
4. Same rules apply to direct client lookup by ID/email/subId/Telegram ID, bulk actions, imports/exports, token API calls, websocket events, bots, nodes, settings, and subscription lookups.
5. Root only: staff-account creation, permission edits, owner changes. Sudo cannot inherit owner-only privileges even with overrides.
6. Subscriptions are public bearer secrets. Use unpredictable IDs, enforce ownership before profile selection, partition cache keys by owner and subscriber, and never leak another tenant's credentials.
7. Use user-specific 2FA, login epoch revocation and user-owned API tokens. Existing global TOTP and admin tokens require a safe migration.
8. Changes to configuration files, execution settings, system networking and panel updates default to owner-only until explicitly audited.

## Verified 3x-ui integration points
- `internal/database/model/model.go`: User lacks role; Inbound already stores UserId; ClientRecord lacks owner; ApiToken lacks associated user.
- `internal/web/service/panel/user.go` + `internal/web/session/session.go`: login credentials, session by user ID, login epoch.
- `internal/web/controller/api.go`: currently assigns GetFirstUser() to bearer and node-mTLS requests, needs identity separation **before** any lower-role user is active.
- `internal/web/service/inbound.go`: GetInbounds(userId) scopes listing, GetInbound(id) does not. Mutating direct lookups must be protected.
- `internal/web/controller/client.go`: client list and lookup currently unscoped.
- `internal/sub/controller.go` + `internal/sub/service.go`: global page title, support URL, templates; must resolve per client owner.

## Planned additive tables/columns (NOT in this commit)
- users: role, enabled, creator_user_id, per-account 2FA seed, version/epoch, display name. Preserve original bootstrap owner.
- clients: indexed owner_user_id; existing clients map to confirmed legacy owner only in one-owner installations; ambiguous setups get a migration stop.
- user_permissions(user_id, action, data_scope), inbound_assignments(inbound_id, user_id, can_create).
- admin_subscription_profiles(user_id, title, support_id, support_url, remark_template, share_template, page_template, verified_host).
- api_tokens.user_id tied to actual actor and scoped token privilege.
- admin_audit_events: actor/resource/action/outcome/time without secrets.

## Delivery sequence
1. **This PR:** standalone default-deny Role/Action/DataScope engine and negative unit tests; no runtime behavior change.
2. Add schema migrations and owner bootstrap, disabled-by-default staff provisioning, per-account 2FA/session/token handling.
3. Add middleware and *scoped* repository operations across all read/write routes, realtime, bots, imports and node operations; comprehensive shared-inbound isolation tests.
4. Add per-admin profile management, safe validated templates and subscription delivery by client owner, dedicated cache partitioning.
5. Add owner UI and E2E test matrix; staging backups, rollback and release verification on SQLite/PostgreSQL.
6. Only after gates pass, enable staff accounts on staging, then ship a reviewed release.

## Mandatory tests before rollout
- Reseller A and B share inbound X: neither can get/update/delete/renew/reset/list/export/sub/read websocket data for other's clients.
- Forged user IDs, raw API token, guessable paths and import endpoints cannot bypass permission.
- Owner disables a staff member: session and tokens stop working immediately; clients keep working.
- Per-admin templates/support/branding changes do not cross streams or poison another subscriber cache.
- Legacy backup restore preserves user and client identities, link IDs, expirations, traffic and inbound settings.
