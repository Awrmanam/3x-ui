package controller

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/mhsanaei/3x-ui/v3/internal/authz"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/dbtest"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service/panel"
	"github.com/mhsanaei/3x-ui/v3/internal/web/session"
)

func TestStaffAPIDeniesUnscopedLegacyRoutes(t *testing.T) {
	dbtest.InitDB(t, filepath.Join(t.TempDir(), "staff-api.db"))
	staffSvc := panel.StaffService{}
	ownerID, err := staffSvc.OwnerID()
	if err != nil {
		t.Fatal(err)
	}
	member, err := staffSvc.Create(ownerID, panel.StaffCreateInput{
		Username: "restricted_staff", Password: "strong-test-pass-0123", Role: authz.RoleReseller, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var owner model.User
	if err := database.GetDB().First(&owner, ownerID).Error; err != nil {
		t.Fatal(err)
	}
	var subordinate model.User
	if err := database.GetDB().First(&subordinate, member.UserID).Error; err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	api := &APIController{}
	for _, tc := range []struct {
		name, path string
		user       *model.User
		want       int
	}{
		{"member cannot list global clients", "/panel/api/clients/list", &subordinate, http.StatusForbidden},
		{"member cannot fetch backups", "/panel/api/server/getDb", &subordinate, http.StatusForbidden},
		{"member cannot list API tokens", "/panel/api/setting/apiTokens", &subordinate, http.StatusForbidden},
		{"member cannot list all hosts", "/panel/api/hosts/list", &subordinate, http.StatusForbidden},
		{"member cannot list all nodes", "/panel/api/nodes/list", &subordinate, http.StatusForbidden},
		{"member cannot list other administrators", "/panel/api/admins/list", &subordinate, http.StatusForbidden},
		{"member can read own profile", "/panel/api/admins/me/profile", &subordinate, http.StatusOK},
		{"member can read assigned inbound summaries", "/panel/api/admins/me/inbounds", &subordinate, http.StatusOK},
		{"member can view own identity", "/panel/api/admins/me", &subordinate, http.StatusOK},
		{"member can list own clients", "/panel/api/admins/me/clients", &subordinate, http.StatusOK},
		{"owner retains global client access", "/panel/api/clients/list", &owner, http.StatusOK},
		{"anonymous cannot enter", "/panel/api/clients/list", nil, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.Use(sessions.Sessions("3x-ui", cookie.NewStore([]byte("sufficiently-long-test-cookie-secret"))))
			router.GET(tc.path, func(c *gin.Context) {
				if tc.user != nil {
					session.SetAPIAuthUser(c, tc.user)
				}
				c.Next()
			}, api.enforceStaffScope, func(c *gin.Context) { c.Status(http.StatusOK) })
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			router.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("%s returned %d, wanted %d, body=%s", tc.path, rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}
