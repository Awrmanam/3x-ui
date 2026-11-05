package panel

import (
 "path/filepath"
 "testing"

 "github.com/mhsanaei/3x-ui/v3/internal/authz"
 "github.com/mhsanaei/3x-ui/v3/internal/database"
 "github.com/mhsanaei/3x-ui/v3/internal/database/dbtest"
 "github.com/mhsanaei/3x-ui/v3/internal/database/model"
)

const staffTestPassword = "secure-passphrase-123"

func initStaffTestDB(t *testing.T) (StaffService,int) {
 t.Helper()
 dbtest.InitDB(t,filepath.Join(t.TempDir(),"staff-xui.db"))
 svc:=StaffService{}
 owner,err:=svc.OwnerID()
 if err!=nil||owner<=0{t.Fatalf("bootstrap owner: id=%d error=%v",owner,err)}
 return svc,owner
}
func createTestStaff(t *testing.T,svc StaffService,owner int,name string)(*model.StaffAccount) {
 t.Helper()
 account,err:=svc.Create(owner,StaffCreateInput{
  Username:name,Password:staffTestPassword,Role:authz.RoleReseller,Enabled:true,
 })
 if err!=nil{t.Fatalf("create %s: %v",name,err)}
 return account
}
func TestStaffOwnerAnchorAndRolePrivilege(t *testing.T) {
 svc,owner:=initStaffTestDB(t)
 alice:=createTestStaff(t,svc,owner,"staff_alice")
 if svc.IsOwner(alice.UserID)||!svc.IsOwner(owner){t.Fatal("owner identity drift")}
 if _,err:=svc.Create(alice.UserID,StaffCreateInput{
  Username:"illicit_user",Password:staffTestPassword,Role:authz.RoleAdmin,Enabled:true,
 });err==nil{t.Fatal("staff granted account creation")}
 if _,err:=svc.Create(owner,StaffCreateInput{
  Username:"illicit_owner",Password:staffTestPassword,Role:authz.RoleOwner,Enabled:true,
 });err==nil{t.Fatal("new root created")}
 if _,err:=svc.Create(owner,StaffCreateInput{
  Username:"staff_alice",Password:staffTestPassword,Role:authz.RoleReseller,Enabled:true,
 });err==nil{t.Fatal("duplicate username created")}
 if _,err:=svc.Create(owner,StaffCreateInput{
  Username:"shortpass",Password:"short",Role:authz.RoleReseller,Enabled:true,
 });err==nil{t.Fatal("weak password accepted")}
 p,err:=svc.ResolvePrincipal(alice.UserID)
 if err!=nil||p.Role!=authz.RoleReseller {t.Fatalf("role mismatch %v %v",p.Role,err)}
 if p.Allows(authz.AdminsManage,owner,true){t.Fatal("staff can manage root")}
 if _,err:=svc.List(alice.UserID);err==nil{t.Fatal("staff listed all accounts")}
}
func TestStaffLoginDisableAndEpoch(t *testing.T) {
 svc,owner:=initStaffTestDB(t)
 a:=createTestStaff(t,svc,owner,"staff_login")
 us:=UserService{}
 who,err:=us.CheckUser(a.Username,staffTestPassword,"")
 if err!=nil||who==nil||who.Id!=a.UserID{t.Fatalf("staff login failed %v",err)}
 before:=who.LoginEpoch
 disabled:=false
 if err:=svc.Update(owner,a.UserID,StaffUpdateInput{Enabled:&disabled});err!=nil{t.Fatal(err)}
 if _,err:=us.CheckUser(a.Username,staffTestPassword,"");err==nil{t.Fatal("disabled staff logged in")}
 var after model.User
 if err:=database.GetDB().First(&after,a.UserID).Error;err!=nil{t.Fatal(err)}
 if after.LoginEpoch<=before{t.Fatal("disabling did not revoke existing sessions")}
}
func TestStaffPermissionAndProfileIsolation(t *testing.T) {
 svc,owner:=initStaffTestDB(t)
 alice:=createTestStaff(t,svc,owner,"staff_alpha")
 bob:=createTestStaff(t,svc,owner,"staff_beta")
 if err:=svc.SetPermissions(alice.UserID,bob.UserID,nil);err==nil{t.Fatal("staff managed permissions")}
 bad:=[]model.StaffPermission{{Action:string(authz.OwnerManage),DataScope:string(authz.ScopeAll)}}
 if err:=svc.SetPermissions(owner,alice.UserID,bad);err==nil{t.Fatal("owner-only grant permitted")}
 grants:=[]model.StaffPermission{{Action:string(authz.ClientsRead),DataScope:string(authz.ScopeNone)}}
 if err:=svc.SetPermissions(owner,alice.UserID,grants);err!=nil{t.Fatal(err)}
 p,err:=svc.ResolvePrincipal(alice.UserID)
 if err!=nil{t.Fatal(err)}
 if p.Allows(authz.ClientsRead,alice.UserID,false){t.Fatal("revoked client read still allowed")}
 if err:=svc.SetProfile(alice.UserID,bob.UserID,model.StaffSubscriptionProfile{Title:"stolen"});err==nil{
  t.Fatal("cross staff profile write")
 }
 if err:=svc.SetProfile(owner,alice.UserID,model.StaffSubscriptionProfile{
  Title:"Alpha VPN",SupportID:"alpha_support",SupportURL:"https://t.me/alpha_support",
 });err!=nil{t.Fatal(err)}
 actual,err:=svc.GetProfile(alice.UserID,alice.UserID)
 if err!=nil||actual.Title!="Alpha VPN"{t.Fatalf("profile not persisted %v",err)}
 if _,err:=svc.GetProfile(bob.UserID,alice.UserID);err==nil{t.Fatal("cross staff profile read")}
 if err:=svc.SetProfile(owner,bob.UserID,model.StaffSubscriptionProfile{
  SupportURL:"javascript:alert(1)",
 });err==nil{t.Fatal("unsafe support URL allowed")}
}
func TestStaffInboundAssignmentsVerifyOwner(t *testing.T) {
 svc,owner:=initStaffTestDB(t)
 alice:=createTestStaff(t,svc,owner,"assigned_alpha")
 bob:=createTestStaff(t,svc,owner,"assigned_beta")
 ib:=model.Inbound{UserId:owner,Tag:"safe-ib",Protocol:model.VLESS,Remark:"Shared"}
 if err:=database.GetDB().Create(&ib).Error;err!=nil{t.Fatal(err)}
 outside:=model.Inbound{UserId:bob.UserID,Tag:"other-ib",Protocol:model.VLESS}
 if err:=database.GetDB().Create(&outside).Error;err!=nil{t.Fatal(err)}
 good:=[]model.StaffInboundAssignment{{InboundID:ib.Id,CanCreate:true}}
 if err:=svc.SetAssignments(owner,alice.UserID,good);err!=nil{t.Fatal(err)}
 rows,err:=svc.ListAssignments(alice.UserID,alice.UserID)
 if err!=nil||len(rows)!=1||rows[0].InboundID!=ib.Id{t.Fatalf("assignments %#v %v",rows,err)}
 if _,err:=svc.ListAssignments(bob.UserID,alice.UserID);err==nil{t.Fatal("cross staff assignments read")}
 bad:=[]model.StaffInboundAssignment{{InboundID:outside.Id,CanCreate:true}}
 if err:=svc.SetAssignments(owner,alice.UserID,bad);err==nil{t.Fatal("assigned another staff inbound")}
 rows,err=svc.ListAssignments(owner,alice.UserID)
 if err!=nil||len(rows)!=1||rows[0].InboundID!=ib.Id{t.Fatal("failed assignment replaced prior valid set")}
}
func TestStaffClientLedgerFailsClosedAcrossResellers(t *testing.T) {
 svc,owner:=initStaffTestDB(t)
 alice:=createTestStaff(t,svc,owner,"own_alice")
 bob:=createTestStaff(t,svc,owner,"own_bob")
 records:=[]model.ClientRecord{
  {Email:"alice-vpn",SubID:"sub-alice",Enable:true},
  {Email:"bob-vpn",SubID:"sub-bob",Enable:true},
  {Email:"legacy-vpn",SubID:"sub-legacy",Enable:true},
 }
 for i:=range records {
  if err:=database.GetDB().Create(&records[i]).Error;err!=nil{t.Fatal(err)}
 }
 owners:=[]model.StaffClientOwnership{
  {Email:"alice-vpn",UserID:alice.UserID,State:"active"},
  {Email:"bob-vpn",UserID:bob.UserID,State:"active"},
 }
 for i:=range owners {
  if err:=database.GetDB().Create(&owners[i]).Error;err!=nil{t.Fatal(err)}
 }
 clients:=StaffClientService{}
 ar,err:=clients.List(alice.UserID)
 if err!=nil||len(ar)!=1||ar[0].Email!="alice-vpn"{t.Fatalf("alice leaked clients %#v %v",ar,err)}
 if _,err:=clients.Get(alice.UserID,"bob-vpn");err==nil{t.Fatal("alice read bob secret")}
 if _,err:=clients.Get(alice.UserID,"legacy-vpn");err==nil{t.Fatal("alice adopted legacy owner client")}
 if _,err:=clients.List(owner);err==nil{t.Fatal("owner unexpectedly routed through staff clients")}
}


func TestOwnerAnchorNeverReassignsToReseller(t *testing.T) {
 svc,owner:=initStaffTestDB(t)
 alice:=createTestStaff(t,svc,owner,"tenant_after_owner")
 if err:=database.GetDB().Where("id = ?",owner).Delete(&model.User{}).Error;err!=nil{t.Fatal(err)}
 if _,err:=svc.OwnerID();err==nil{t.Fatal("orphaned bootstrap owner automatically reassigned")}
 if svc.IsOwner(alice.UserID){t.Fatal("reseller escalated after owner deletion")}
}

func TestDisabledStaffCannotReadOwnLedger(t *testing.T) {
 svc,owner:=initStaffTestDB(t)
 staff:=createTestStaff(t,svc,owner,"tenant_disabled")
 disabled:=false
 if err:=svc.Update(owner,staff.UserID,StaffUpdateInput{Enabled:&disabled});err!=nil{t.Fatal(err)}
 if _,err:= (StaffClientService{}).List(staff.UserID);err==nil{
  t.Fatal("disabled staff retained client list access")
 }
}
