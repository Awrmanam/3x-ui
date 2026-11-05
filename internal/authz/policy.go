// Package authz contains the default-deny policy for multi-admin account roles.
//
// This package is deliberately not wired into the HTTP handlers yet.
// Do not enable subordinate accounts until resource ownership is enforced in
// all REST, subscriptions, tokens, bots, websocket, and service entry points.
package authz

type Role string

const (
	RoleOwner    Role = "owner"
	RoleSudo     Role = "sudo"
	RoleAdmin    Role = "admin"
	RoleReseller Role = "reseller"
	RoleCustom   Role = "custom"
)

type Action string

const (
	OwnerManage       Action = "owner.manage"
	AdminsRead        Action = "admins.read"
	AdminsManage      Action = "admins.manage"
	PermissionsManage Action = "permissions.manage"
	InboundsRead      Action = "inbounds.read"
	InboundsCreate    Action = "inbounds.create"
	InboundsUpdate    Action = "inbounds.update"
	InboundsDelete    Action = "inbounds.delete"
	ClientsRead       Action = "clients.read"
	ClientsCreate     Action = "clients.create"
	ClientsUpdate     Action = "clients.update"
	ClientsDelete     Action = "clients.delete"
	ClientsReset      Action = "clients.reset_traffic"
	SubsRead          Action = "subscriptions.read"
	SubsManage        Action = "subscriptions.manage"
	TemplatesManage   Action = "templates.manage"
	HostsRead         Action = "hosts.read"
	HostsManage       Action = "hosts.manage"
	NodesRead         Action = "nodes.read"
	NodesManage       Action = "nodes.manage"
	TrafficRead       Action = "traffic.read"
	SettingsRead      Action = "settings.read"
	SettingsManage    Action = "settings.manage"
	RoutingManage     Action = "routing.manage"
	TokensManage      Action = "tokens.manage"
	BackupExport      Action = "backups.export"
	BackupRestore     Action = "backups.restore"
	SystemRead        Action = "system.read"
	SystemManage      Action = "system.manage"
	AuditRead         Action = "audit.read"
)

type DataScope string

const (
	ScopeNone          DataScope = "none"
	ScopeOwn           DataScope = "own"
	ScopeAssigned      DataScope = "assigned"
	ScopeOwnOrAssigned DataScope = "own_or_assigned"
	ScopeAll           DataScope = "all"
)

var knownActions = map[Action]struct{}{
	OwnerManage: {}, AdminsRead: {}, AdminsManage: {}, PermissionsManage: {},
	InboundsRead: {}, InboundsCreate: {}, InboundsUpdate: {}, InboundsDelete: {},
	ClientsRead: {}, ClientsCreate: {}, ClientsUpdate: {}, ClientsDelete: {}, ClientsReset: {},
	SubsRead: {}, SubsManage: {}, TemplatesManage: {}, HostsRead: {}, HostsManage: {},
	NodesRead: {}, NodesManage: {}, TrafficRead: {}, SettingsRead: {}, SettingsManage: {},
	RoutingManage: {}, TokensManage: {}, BackupExport: {}, BackupRestore: {},
	SystemRead: {}, SystemManage: {}, AuditRead: {},
}

var reservedActions = map[Action]struct{}{
	OwnerManage: {}, AdminsManage: {}, PermissionsManage: {},
}

func ValidRole(role Role) bool {
	switch role {
	case RoleOwner, RoleSudo, RoleAdmin, RoleReseller, RoleCustom:
		return true
	default:
		return false
	}
}
func ValidAction(action Action) bool { _, ok := knownActions[action]; return ok }
func ValidScope(scope DataScope) bool {
	switch scope {
	case ScopeNone, ScopeOwn, ScopeAssigned, ScopeOwnOrAssigned, ScopeAll:
		return true
	default:
		return false
	}
}

// Defaults returns a new map. Presets are not a substitute for a scoped query.
func Defaults(role Role) map[Action]DataScope {
	grants := make(map[Action]DataScope)
	switch role {
	case RoleOwner:
		for a := range knownActions {
			grants[a] = ScopeAll
		}
	case RoleSudo:
		for _, a := range []Action{
			InboundsRead, InboundsCreate, InboundsUpdate, InboundsDelete,
			ClientsRead, ClientsCreate, ClientsUpdate, ClientsDelete, ClientsReset,
			SubsRead, SubsManage, TemplatesManage, HostsRead, HostsManage,
			NodesRead, TrafficRead, SystemRead, AuditRead,
		} {
			grants[a] = ScopeAll
		}
	case RoleAdmin:
		for _, a := range []Action{
			InboundsRead, InboundsCreate, InboundsUpdate, InboundsDelete,
			ClientsRead, ClientsCreate, ClientsUpdate, ClientsDelete, ClientsReset,
			SubsRead, SubsManage, TemplatesManage, HostsRead, HostsManage, TrafficRead,
		} {
			grants[a] = ScopeOwn
		}
	case RoleReseller:
		grants[InboundsRead] = ScopeAssigned
		for _, a := range []Action{
			ClientsRead, ClientsCreate, ClientsUpdate, ClientsDelete,
			ClientsReset, SubsRead, SubsManage, TemplatesManage, TrafficRead,
		} {
			grants[a] = ScopeOwn
		}
	}
	return grants
}

// Principal must be loaded from authenticated server-side storage, never request JSON.
// Only an immutable bootstrap owner may be persisted with RoleOwner.
type Principal struct {
	UserID    int
	Role      Role
	Enabled   bool
	Overrides map[Action]DataScope
}

func (p Principal) ScopeFor(action Action) DataScope {
	if !p.Enabled || p.UserID <= 0 || !ValidRole(p.Role) || !ValidAction(action) {
		return ScopeNone
	}
	if p.Role == RoleOwner {
		return ScopeAll
	}
	if _, reserved := reservedActions[action]; reserved {
		return ScopeNone
	}
	if scope, ok := p.Overrides[action]; ok {
		if ValidScope(scope) {
			return scope
		}
		return ScopeNone
	}
	return Defaults(p.Role)[action]
}

// Allows is an individual-resource policy, not a list filter.
// Resolve owner ID and assignment in DB; never accept them from the client.
func (p Principal) Allows(action Action, resourceOwnerID int, assigned bool) bool {
	switch p.ScopeFor(action) {
	case ScopeAll:
		return true
	case ScopeOwn:
		return resourceOwnerID > 0 && resourceOwnerID == p.UserID
	case ScopeAssigned:
		return resourceOwnerID > 0 && assigned
	case ScopeOwnOrAssigned:
		return resourceOwnerID > 0 && (resourceOwnerID == p.UserID || assigned)
	default:
		return false
	}
}
