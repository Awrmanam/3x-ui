package authz

import "testing"

func TestOwnerAndUnknownDeny(t *testing.T) {
	owner := Principal{UserID: 1, Role: RoleOwner, Enabled: true}
	for a := range knownActions {
		if !owner.Allows(a, 0, false) {
			t.Fatalf("owner denied %s", a)
		}
	}
	if (Principal{Role: RoleOwner, Enabled: true}).Allows(ClientsRead, 1, false) {
		t.Fatal("missing id admitted")
	}
	if owner.Allows("nonexistent", 1, false) {
		t.Fatal("unknown action admitted")
	}
	if (Principal{UserID: 1, Role: RoleOwner}).Allows(ClientsRead, 1, false) {
		t.Fatal("disabled owner admitted")
	}
}

func TestAdminIsolation(t *testing.T) {
	p := Principal{UserID: 10, Role: RoleAdmin, Enabled: true}
	if !p.Allows(ClientsRead, 10, false) {
		t.Fatal("own read denied")
	}
	if p.Allows(ClientsRead, 20, false) || p.Allows(ClientsUpdate, 20, true) {
		t.Fatal("cross tenant leaked")
	}
	if p.Allows(SettingsManage, 10, false) {
		t.Fatal("global settings granted")
	}
}

func TestResellerAssignmentIsNotClientOwnership(t *testing.T) {
	p := Principal{UserID: 30, Role: RoleReseller, Enabled: true}
	if !p.Allows(InboundsRead, 1, true) {
		t.Fatal("assigned inbound denied")
	}
	if p.Allows(InboundsRead, 1, false) || p.Allows(InboundsUpdate, 1, true) {
		t.Fatal("inbound privilege escaped")
	}
	if p.Allows(ClientsRead, 40, true) {
		t.Fatal("other reseller's client leaked")
	}
	if !p.Allows(ClientsCreate, 30, false) {
		t.Fatal("own client creation denied")
	}
}

func TestOverridesDefaultDenyAndReserved(t *testing.T) {
	p := Principal{UserID: 44, Role: RoleCustom, Enabled: true}
	if p.Allows(ClientsRead, 44, false) {
		t.Fatal("custom unexpectedly privileged")
	}
	p.Overrides = map[Action]DataScope{ClientsRead: ScopeOwnOrAssigned, AdminsManage: ScopeAll}
	if !p.Allows(ClientsRead, 44, false) || !p.Allows(ClientsRead, 45, true) {
		t.Fatal("override denied")
	}
	if p.Allows(ClientsRead, 45, false) || p.Allows(AdminsManage, 44, true) {
		t.Fatal("override escaped scope")
	}
	p.Overrides[ClientsRead] = "unexpected"
	if p.Allows(ClientsRead, 44, false) {
		t.Fatal("invalid scope granted")
	}
}

func TestSudoCannotTakeOwnerCredentials(t *testing.T) {
	p := Principal{UserID: 2, Role: RoleSudo, Enabled: true}
	if !p.Allows(ClientsDelete, 50, false) {
		t.Fatal("sudo ops denied")
	}
	for _, a := range []Action{
		OwnerManage, AdminsManage, PermissionsManage, TokensManage,
		BackupRestore, SettingsManage, SystemManage,
	} {
		if p.Allows(a, 1, true) {
			t.Fatalf("sudo gained reserved capability %s", a)
		}
	}
}

func TestDefaultsIndependent(t *testing.T) {
	m := Defaults(RoleReseller)
	m[ClientsRead] = ScopeAll
	if Defaults(RoleReseller)[ClientsRead] != ScopeOwn {
		t.Fatal("defaults mutated")
	}
}

func TestDisabledPrincipalAlwaysDeny(t *testing.T) {
	p := Principal{UserID: 5, Role: RoleReseller, Enabled: false, Overrides: map[Action]DataScope{ClientsRead: ScopeAll}}
	if p.Allows(ClientsRead, 5, false) {
		t.Fatal("disabled user had access")
	}
}
