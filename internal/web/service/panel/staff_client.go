package panel

import (
 "errors"
 "fmt"
 "strings"

 "github.com/mhsanaei/3x-ui/v3/internal/authz"
 "github.com/mhsanaei/3x-ui/v3/internal/database"
 "github.com/mhsanaei/3x-ui/v3/internal/database/model"
 "github.com/mhsanaei/3x-ui/v3/internal/web/service"
 "gorm.io/gorm"
)

var ErrStaffClientNotFound = errors.New("staff client not found")

// StaffClientService uses a dedicated table so legacy clients are never
// automatically assigned to an arbitrary reseller on first migration.
type StaffClientService struct {
 Staff StaffService
 Client service.ClientService
 Inbound service.InboundService
}

func normalizeStaffEmail(email string) string {
 return strings.ToLower(strings.TrimSpace(email))
}

func (s StaffClientService) can(userID int, action authz.Action) error {
 p,err:=s.Staff.ResolvePrincipal(userID)
 if err!=nil{return err}
 if p.Role==authz.RoleOwner{return errors.New("owner should use the existing clients API")}
 if !p.Enabled || p.ScopeFor(action)==authz.ScopeNone {
  return errors.New("client action not permitted")
 }
 return nil
}
func (s StaffClientService) assigned(userID,inboundID int,write bool) error {
 if inboundID<=0{return errors.New("invalid inbound id")}
 var a model.StaffInboundAssignment
 if err:=database.GetDB().Where("user_id = ? AND inbound_id = ?",userID,inboundID).First(&a).Error;err!=nil{
  return errors.New("inbound is not assigned to your account")
 }
 if write && !a.CanCreate{return errors.New("inbound is read-only")}
 ownerID,err:=s.Staff.OwnerID()
 if err!=nil{return err}
 var count int64
 if err:=database.GetDB().Model(&model.Inbound{}).
  Where("id = ? AND user_id = ?",inboundID,ownerID).Count(&count).Error;err!=nil{return err}
 if count!=1{return errors.New("inbound is no longer eligible for staff access")}
 return nil
}
func (s StaffClientService) ensureOwned(userID int,email string) error {
 email=normalizeStaffEmail(email)
 var item model.StaffClientOwnership
 if err:=database.GetDB().Where("email = ? AND user_id = ? AND state = ?",email,userID,"active").First(&item).Error;err!=nil{
  return ErrStaffClientNotFound
 }
 return nil
}
// ensureClientInboundsAssigned disallows a reseller mutation if any endpoint
// for this client has since been attached by owner to an unassigned inbound.
func (s StaffClientService) ensureClientInboundsAssigned(userID int,email string) error {
 var ids []int
 err:=database.GetDB().Table("client_inbounds AS ci").
  Joins("JOIN clients AS c ON c.id = ci.client_id").
  Where("c.email = ?",normalizeStaffEmail(email)).
  Pluck("ci.inbound_id",&ids).Error
 if err!=nil{return err}
 if len(ids)==0{return ErrStaffClientNotFound}
 for _,id:=range ids {
  if err:=s.assigned(userID,id,true);err!=nil{return err}
 }
 return nil
}
func (s StaffClientService) List(userID int) ([]model.ClientRecord,error) {
 if err:=s.can(userID,authz.ClientsRead);err!=nil{return nil,err}
 var out []model.ClientRecord
 err:=database.GetDB().Model(&model.ClientRecord{}).
  Joins("JOIN staff_client_ownership AS owner ON owner.email = clients.email").
  Where("owner.user_id = ? AND owner.state = ?",userID,"active").
  Order("clients.id desc").Limit(1000).Find(&out).Error
 return out,err
}
func (s StaffClientService) Get(userID int,email string)(*model.ClientRecord,error){
 if err:=s.can(userID,authz.ClientsRead);err!=nil{return nil,err}
 if err:=s.ensureOwned(userID,email);err!=nil{return nil,err}
 var c model.ClientRecord
 err:=database.GetDB().Where("email = ?",normalizeStaffEmail(email)).First(&c).Error
 if err!=nil{return nil,ErrStaffClientNotFound}
 return &c,nil
}
// Create reserves a globally unique email BEFORE touching Xray and records
// the tenant even when a partial inbound apply committed then returned an error.
// A legacy/global email can never be adopted by staff through this API.
func (s StaffClientService) Create(userID int,payload *service.ClientCreatePayload)(bool,error){
 if err:=s.can(userID,authz.ClientsCreate);err!=nil{return false,err}
 if payload==nil||len(payload.InboundIds)==0{return false,errors.New("inbound selection required")}
 email:=normalizeStaffEmail(payload.Client.Email)
 if email==""{return false,errors.New("client email required")}
 seen:=map[int]bool{}
 for _,id:=range payload.InboundIds {
  if seen[id]{continue}
  seen[id]=true
  if err:=s.assigned(userID,id,true);err!=nil{return false,err}
 }
 payload.Client.Email=email
 // A new identity must receive a fresh random subscription secret.
 // Reusing a supplied subId could reveal an existing subscriber's links.
 payload.Client.SubID=""
 err:=database.GetDB().Transaction(func(tx *gorm.DB)error{
  var existing int64
  if err:=tx.Model(&model.ClientRecord{}).Where("LOWER(email) = ?",email).Count(&existing).Error;err!=nil{return err}
  if existing!=0{return errors.New("client email already exists")}
  if err:=tx.Model(&model.StaffClientOwnership{}).Where("email = ?",email).Count(&existing).Error;err!=nil{return err}
  if existing!=0{return errors.New("email already reserved by a staff account")}
  return tx.Create(&model.StaffClientOwnership{Email:email,UserID:userID,State:"reserved"}).Error
 })
 if err!=nil{return false,err}
 restart,creationErr:=s.Client.Create(&s.Inbound,payload)
 // The original ClientService may partially commit on an error. If it did,
 // retain ownership instead of exposing an ownerless unaccounted client.
 var exists int64
 lookupErr:=database.GetDB().Model(&model.ClientRecord{}).Where("email = ?",email).Count(&exists).Error
 if lookupErr!=nil{return restart,errors.Join(creationErr,lookupErr)}
 if creationErr!=nil{
  // On any partial/ambiguous error, quarantine the reservation. In
  // particular, a concurrent owner-created client must NEVER become a
  // reseller client merely because an email now exists in the database.
  if exists>0{
   _=database.GetDB().Model(&model.StaffClientOwnership{}).
    Where("email = ? AND user_id = ?",email,userID).Update("state","needs_review").Error
  }else{
   _=database.GetDB().Where("email = ? AND user_id = ? AND state = ?",email,userID,"reserved").Delete(&model.StaffClientOwnership{}).Error
  }
  return restart,creationErr
 }
 if exists==0{return restart,errors.New("client create returned without persisting a record")}
 if err:=database.GetDB().Model(&model.StaffClientOwnership{}).
  Where("email = ? AND user_id = ? AND state = ?",email,userID,"reserved").Update("state","active").Error;err!=nil{
  return restart,err
 }
 return restart,nil
}
func (s StaffClientService) Update(userID int,email string,client model.Client,limitHwid int,inboundFilter []int)(bool,error) {
 if err:=s.can(userID,authz.ClientsUpdate);err!=nil{return false,err}
 if err:=s.ensureOwned(userID,email);err!=nil{return false,err}
 if err:=s.ensureClientInboundsAssigned(userID,email);err!=nil{return false,err}
 for _,id:=range inboundFilter {
  if err:=s.assigned(userID,id,true);err!=nil{return false,err}
 }
 if strings.TrimSpace(client.Email)!="" && normalizeStaffEmail(client.Email)!=normalizeStaffEmail(email) {
  return false,errors.New("staff cannot rename clients through this endpoint")
 }
 return s.Client.UpdateByEmail(&s.Inbound,normalizeStaffEmail(email),client,limitHwid,inboundFilter...)
}
func (s StaffClientService) Delete(userID int,email string)(bool,error){
 if err:=s.can(userID,authz.ClientsDelete);err!=nil{return false,err}
 if err:=s.ensureOwned(userID,email);err!=nil{return false,err}
 if err:=s.ensureClientInboundsAssigned(userID,email);err!=nil{return false,err}
 restart,err:=s.Client.DeleteByEmail(&s.Inbound,normalizeStaffEmail(email),false)
 if err!=nil{return restart,err}
 if e:=database.GetDB().Where("email = ? AND user_id = ?",normalizeStaffEmail(email),userID).
  Delete(&model.StaffClientOwnership{}).Error;e!=nil{return restart,fmt.Errorf("client deleted but ownership cleanup failed: %w",e)}
 return restart,nil
}

// Links is restricted to an authenticated member's own persisted client.
// Calling GetAllClientLinks without ownership verification would expose
// credentials for any guessed email, so never use the unscoped API in staff UI.
func (s StaffClientService) Links(userID int,email,host string) ([]string,error) {
 if err:=s.can(userID,authz.SubsRead);err!=nil{return nil,err}
 if err:=s.ensureOwned(userID,email);err!=nil{return nil,err}
 // Do not publish links if the client was attached to a removed/reassigned
 // inbound; administrators must repair its assignments first.
 if err:=s.ensureClientInboundsAssigned(userID,email);err!=nil{return nil,err}
 return s.Inbound.GetAllClientLinks(host,normalizeStaffEmail(email))
}
