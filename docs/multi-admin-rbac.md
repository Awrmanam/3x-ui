# Multi-admin / reseller isolation — architecture and rollout gate

**Status: prototype under active implementation.** Account creation, selected staff UI, owner-managed roles/grants, a separate scoped client CRUD path, staff subscription metadata, session deactivation, and additive tables have been committed to a DRAFT PR. **The whole-system migration/build, negative tests, backend boundary audit, and deployment validation are NOT complete. DO NOT MERGE OR INSTALL IN PRODUCTION.**

**Safety model:** the original general-purpose panel APIs and broadcast websocket are owner-only for staff sessions. Staff accounts enter an intentionally reduced separate `/panel/admins` UI with scoped operations. This is not a full replacement for the inherited panel experience and role permutations are not yet end-to-end functional.

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

## New tables committed on the feature branch (not deployed)
- `admin_root`: stable first-user owner anchor, with explicit no-reassignment behavior.
- `staff_accounts`: role, enabled, creator, optional per-account TOTP seed; credentials remain in `users`, session revocation reuses `login_epoch`.
- `staff_client_ownership`: separate email→owner ledger with reserved/active/needs_review states; old clients remain unassigned and root-only.
- `staff_permissions(user_id, action, data_scope)`, `staff_inbound_assignments(inbound_id, user_id, can_create)`.
- `staff_subscription_profiles(user_id, title, support_id, support_url, remark_template, share_link_template, page_template, subscription_base_url)`: title/support/remark applied, other requested template and base-URL fields still persistence-only.
- **NOT IMPLEMENTED:** per-user API tokens; legacy API tokens remain restricted to the original owner identity.
- **NOT IMPLEMENTED:** staff audit log and per-account TOTP provisioning UI.

## Implementation status as of 2026-11-05

**Implemented in draft source:**
- Backend: owner staff CRUD, user enable/disable, password replacement and session epochs, role/grant and inbound assignment APIs, separate staff client read/create/update/delete/link endpoints.
- Database: additive schema for all ownership tables; included in normal migration and SQLite→PostgreSQL copy model.
- Frontend: Owner Admins page for staff management, granular overrides, inbound assignment, and profile settings; reduced staff UI for assigned inbounds, own clients and link extraction.
- Public subscriptions: owner-bound title/support metadata and request-local remark template in raw/JSON/Clash generation; legacy profiles keep global defaults.
- Fail-closed boundaries: non-owner session denied inherited global APIs and cross-tenant WebSocket stream, per-account session deactivation, client ownership ledger.
- Negative unit/integration tests added for privilege, credentials and tenant isolation.

**Important open gates:**
1. **CI is not running on the GitHub fork yet:** no builds or Go/frontend tests have been observed for this PR. Source compiles are not established.
2. Two resellers sharing one inbound need **real end-to-end Xray/SQL/traffic tests**, especially partial creates, deletes, resets, subscription generation and allowed inbounds.
3. Full per-role module grants and own inbound management are not available in the staff UI; only a limited safe subset is implemented.
4. Per-admin **share-link templates, page templates, subscription base URI** have validated storage but are not connected to rendering; domain ownership verification is missing.
5. Staff-specific 2FA enrollment, per-user API tokens and audit log must be designed and tested before release.
6. Negative tests and cross-DB migration, restore, upgrade, and rollback tests must pass before production. No server rollout has been attempted.

## Delivery sequence

. **This PR:** standalone default-deny Role/Action/DataScope engine and negative unit tests; no runtime behavior change.
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
