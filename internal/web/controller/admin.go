package controller

import (
 "net/http"
 "strconv"

 "github.com/mhsanaei/3x-ui/v3/internal/authz"
 "github.com/mhsanaei/3x-ui/v3/internal/database"
 "github.com/mhsanaei/3x-ui/v3/internal/database/model"
 "github.com/mhsanaei/3x-ui/v3/internal/web/service"
 "github.com/mhsanaei/3x-ui/v3/internal/web/service/panel"
 "github.com/mhsanaei/3x-ui/v3/internal/web/session"
 "github.com/gin-gonic/gin"
)

// AdminController is intentionally isolated from the inherited all-powerful
// inbound/client APIs. It never trusts owner/user identity from request JSON.
type AdminController struct{staff panel.StaffService}

func NewAdminController(g *gin.RouterGroup) *AdminController {
 a:=&AdminController{}
 g.GET("/me",a.me)
 g.GET("/me/profile",a.myProfile)
 g.POST("/me/profile",a.saveMyProfile)
 g.GET("/me/inbounds",a.myInbounds)
 g.GET("/me/clients",a.listMyClients)
 g.GET("/me/clients/:email",a.getMyClient)
 g.GET("/me/clients/:email/links",a.getMyClientLinks)
 g.GET("/me/clients/:email/sub-links",a.getMyClientSubscriptionLinks)
 g.POST("/me/clients/create",a.createMyClient)
 g.POST("/me/clients/update/:email",a.updateMyClient)
 g.POST("/me/clients/delete/:email",a.deleteMyClient)
 g.GET("/list",a.list)
 g.POST("/create",a.create)
 g.POST("/:id/update",a.update)
 g.GET("/:id/permissions",a.permissions)
 g.POST("/:id/permissions",a.savePermissions)
 g.GET("/:id/inbounds",a.assignments)
 g.POST("/:id/inbounds",a.saveAssignments)
 g.GET("/:id/profile",a.profile)
 g.POST("/:id/profile",a.saveProfile)
 return a
}
func (a *AdminController) actor(c *gin.Context) int {
 u:=session.GetLoginUser(c)
 if u==nil{return 0}
 return u.Id
}
func (a *AdminController) owner(c *gin.Context) bool {
 if !a.staff.IsOwner(a.actor(c)) {
  c.AbortWithStatusJSON(http.StatusForbidden,gin.H{"success":false,"msg":"owner permission required"})
  return false
 }
 return true
}
func adminError(c *gin.Context,code int,err error) {
 c.JSON(code,gin.H{"success":false,"msg":err.Error()})
}
func adminOK(c *gin.Context,obj any) {
 c.JSON(http.StatusOK,gin.H{"success":true,"obj":obj})
}
func (a *AdminController) target(c *gin.Context)(int,bool) {
 id,err:=strconv.Atoi(c.Param("id"))
 if err!=nil||id<=0 {
  c.JSON(http.StatusBadRequest,gin.H{"success":false,"msg":"invalid account ID"})
  return 0,false
 }
 return id,true
}
func (a *AdminController) me(c *gin.Context) {
 user:=session.GetLoginUser(c)
 if user==nil{c.AbortWithStatus(http.StatusUnauthorized);return}
 p,err:=a.staff.ResolvePrincipal(user.Id)
 if err!=nil {adminError(c,http.StatusForbidden,err);return}
 adminOK(c,gin.H{"id":user.Id,"username":user.Username,"role":p.Role,"permissions":p.Overrides})
}
func (a *AdminController) list(c *gin.Context) {
 if !a.owner(c){return}
 rows,err:=a.staff.List(a.actor(c))
 if err!=nil{adminError(c,http.StatusInternalServerError,err);return}
 adminOK(c,rows)
}
func (a *AdminController) create(c *gin.Context) {
 if !a.owner(c){return}
 var in panel.StaffCreateInput
 if err:=c.ShouldBindJSON(&in);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 row,err:=a.staff.Create(a.actor(c),in)
 if err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,row)
}
func (a *AdminController) update(c *gin.Context) {
 if !a.owner(c){return}
 id,ok:=a.target(c);if !ok{return}
 var in panel.StaffUpdateInput
 if err:=c.ShouldBindJSON(&in);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 if err:=a.staff.Update(a.actor(c),id,in);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,true)
}
func (a *AdminController) permissions(c *gin.Context) {
 if !a.owner(c){return}
 id,ok:=a.target(c);if !ok{return}
 rows,err:=a.staff.ListPermissions(a.actor(c),id)
 if err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,rows)
}
func (a *AdminController) savePermissions(c *gin.Context) {
 if !a.owner(c){return}
 id,ok:=a.target(c);if !ok{return}
 var in struct{Permissions []model.StaffPermission `json:"permissions"`}
 if err:=c.ShouldBindJSON(&in);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 if err:=a.staff.SetPermissions(a.actor(c),id,in.Permissions);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,true)
}
func (a *AdminController) assignments(c *gin.Context) {
 if !a.owner(c){return}
 id,ok:=a.target(c);if !ok{return}
 rows,err:=a.staff.ListAssignments(a.actor(c),id)
 if err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,rows)
}
func (a *AdminController) saveAssignments(c *gin.Context) {
 if !a.owner(c){return}
 id,ok:=a.target(c);if !ok{return}
 var in struct{Inbounds []model.StaffInboundAssignment `json:"inbounds"`}
 if err:=c.ShouldBindJSON(&in);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 if err:=a.staff.SetAssignments(a.actor(c),id,in.Inbounds);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,true)
}
func (a *AdminController) myInbounds(c *gin.Context) {
 p,err:=a.staff.ResolvePrincipal(a.actor(c))
 if err!=nil{adminError(c,http.StatusForbidden,err);return}
 if p.ScopeFor(authz.InboundsRead)==authz.ScopeNone {
  c.AbortWithStatus(http.StatusForbidden)
  return
 }
 if p.Role==authz.RoleOwner {
  // Root should use the full existing inbound API.
  adminOK(c,[]any{})
  return
 }
 rows,err:=a.staff.ListAssignments(a.actor(c),a.actor(c))
 if err!=nil{adminError(c,http.StatusForbidden,err);return}
 ids:=make([]int,0,len(rows))
 permissions:=map[int]bool{}
 for _,r:=range rows{ids=append(ids,r.InboundID);permissions[r.InboundID]=r.CanCreate}
 if len(ids)==0{adminOK(c,[]any{});return}
 type safeInbound struct{
  ID int `json:"id"`
  Remark string `json:"remark"`
  Protocol string `json:"protocol"`
  Port int `json:"port"`
  CanCreate bool `json:"canCreate"`
 }
 var inbounds []safeInbound
 ownerID,err:=a.staff.OwnerID()
 if err!=nil{adminError(c,http.StatusForbidden,err);return}
 if err:=database.GetDB().Model(&model.Inbound{}).Select("id, remark, protocol, port").
  Where("id IN ? AND user_id = ?",ids,ownerID).Find(&inbounds).Error;err!=nil {
  adminError(c,http.StatusInternalServerError,err);return
 }
 for i:=range inbounds{inbounds[i].CanCreate=permissions[inbounds[i].ID]}
 adminOK(c,inbounds)
}
func (a *AdminController) profile(c *gin.Context) {
 if !a.owner(c){return}
 id,ok:=a.target(c);if !ok{return}
 item,err:=a.staff.GetProfile(a.actor(c),id)
 if err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,item)
}
func (a *AdminController) saveProfile(c *gin.Context) {
 if !a.owner(c){return}
 id,ok:=a.target(c);if !ok{return}
 a.saveProfileFor(c,id)
}
func (a *AdminController) myProfile(c *gin.Context) {
 item,err:=a.staff.GetProfile(a.actor(c),a.actor(c))
 if err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,item)
}
func (a *AdminController) saveMyProfile(c *gin.Context) {
 a.saveProfileFor(c,a.actor(c))
}
func (a *AdminController) saveProfileFor(c *gin.Context,id int) {
 var input model.StaffSubscriptionProfile
 if err:=c.ShouldBindJSON(&input);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 if err:=a.staff.SetProfile(a.actor(c),id,input);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,true)
}

func staffClientService() panel.StaffClientService {
 return panel.StaffClientService{}
}
func (a *AdminController) listMyClients(c *gin.Context) {
 rows,err:=staffClientService().List(a.actor(c))
 if err!=nil{adminError(c,http.StatusForbidden,err);return}
 adminOK(c,rows)
}
func (a *AdminController) getMyClient(c *gin.Context) {
 row,err:=staffClientService().Get(a.actor(c),c.Param("email"))
 if err!=nil{adminError(c,http.StatusNotFound,err);return}
 adminOK(c,row)
}
func (a *AdminController) createMyClient(c *gin.Context) {
 var payload service.ClientCreatePayload
 if err:=c.ShouldBindJSON(&payload);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 svc:=staffClientService()
 restart,err:=svc.Create(a.actor(c),&payload)
 if restart {a.xrayRestart()}
 if restart || err==nil {notifyClientsChanged()}
 if err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,gin.H{"email":payload.Client.Email,"inboundIds":payload.InboundIds})
}
func (a *AdminController) updateMyClient(c *gin.Context) {
 var req struct {
  model.Client
  LimitHwid int `json:"limitHwid"`
 }
 if err:=c.ShouldBindJSON(&req);err!=nil{adminError(c,http.StatusBadRequest,err);return}
 svc:=staffClientService()
 restart,err:=svc.Update(a.actor(c),c.Param("email"),req.Client,req.LimitHwid,nil)
 if restart {a.xrayRestart()}
 if restart || err==nil {notifyClientsChanged()}
 if err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,true)
}
func (a *AdminController) deleteMyClient(c *gin.Context) {
 svc:=staffClientService()
 restart,err:=svc.Delete(a.actor(c),c.Param("email"))
 if restart {a.xrayRestart()}
 if restart || err==nil {notifyClientsChanged()}
 if err!=nil{adminError(c,http.StatusBadRequest,err);return}
 adminOK(c,true)
}
// Existing node/core restart flags remain controlled by the shared service
// rather than restarting Xray inside HTTP handlers.
func (a *AdminController) xrayRestart() {
 var x service.XrayService
 x.SetToNeedRestart()
}

func (a *AdminController) getMyClientLinks(c *gin.Context) {
 links,err:=staffClientService().Links(a.actor(c),c.Param("email"),resolveHost(c))
 if err!=nil{adminError(c,http.StatusForbidden,err);return}
 adminOK(c,links)
}

func (a *AdminController) getMyClientSubscriptionLinks(c *gin.Context) {
 links,err:=staffClientService().SubscriptionLinks(a.actor(c),c.Param("email"),resolveHost(c))
 if err!=nil{adminError(c,http.StatusForbidden,err);return}
 adminOK(c,links)
}
