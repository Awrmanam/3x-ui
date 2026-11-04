package authz

import "testing"

func TestSubscriptionProfilesRequireOwner(t *testing.T) {
 if ValidateSubscriptionProfile(SubscriptionProfile{})==nil{t.Fatal("ownerless profile admitted")}
 p:=SubscriptionProfile{UserID:10,Title:"Reseller 10",SupportID:"support_test",SupportURL:"https://t.me/support_test",RemarkTemplate:"{{INBOUND}} | {{client}}",ShareLinkTemplate:"xray-default",PageTemplate:"minimal"}
 if err:=ValidateSubscriptionProfile(p);err!=nil{t.Fatalf("valid profile rejected: %v",err)}
 p.UserID=0
 if ValidateSubscriptionProfile(p)==nil{t.Fatal("missing owner admitted")}
}

func TestSubscriptionProfileRejectsUnsafeSettings(t *testing.T) {
 cases:=[]struct{name string; p SubscriptionProfile}{
  {"javascript support",SubscriptionProfile{UserID:1,SupportURL:"javascript:alert(1)"}},
  {"url credentials",SubscriptionProfile{UserID:1,SupportURL:"https://admin:pass@example.com/help"}},
  {"insecure sub URL",SubscriptionProfile{UserID:1,SubscriptionBaseURL:"http://sub.example.com"}},
  {"template path traversal",SubscriptionProfile{UserID:1,PageTemplate:"../../etc/passwd"}},
  {"unknown placeholder",SubscriptionProfile{UserID:1,RemarkTemplate:"{{env_secret}}"}},
  {"unmatched braces",SubscriptionProfile{UserID:1,RemarkTemplate:"{{broken"}},
  {"header newline",SubscriptionProfile{UserID:1,Title:"hello\r\nX-Test: injected"}},
  {"bad support id",SubscriptionProfile{UserID:1,SupportID:"$bad"}},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){if err:=ValidateSubscriptionProfile(tc.p);err==nil{t.Fatal("unsafe profile admitted")}})}
}

func TestSubscriptionProfileEditingIsTenantScoped(t *testing.T) {
 reseller:=Principal{UserID:11,Role:RoleReseller,Enabled:true}
 if !reseller.CanEditSubscriptionProfile(11){t.Fatal("own profile denied")}
 if reseller.CanEditSubscriptionProfile(22){t.Fatal("other reseller's profile granted")}
 reseller.Overrides=map[Action]DataScope{TemplatesManage:ScopeNone}
 if reseller.CanEditSubscriptionProfile(11){t.Fatal("owner-revoked edit permission ignored")}
 owner:=Principal{UserID:1,Role:RoleOwner,Enabled:true}
 if !owner.CanEditSubscriptionProfile(22){t.Fatal("owner cannot manage profile")}
}

func TestCanonicalRemarkTemplate(t *testing.T) {
 p:=SubscriptionProfile{UserID:22,RemarkTemplate:"{{server}} | {{client}} | {{protocol}}"}
 if err:=ValidateSubscriptionProfile(p);err!=nil{t.Fatal(err)}
 got:=CanonicalRemarkTemplate(p.RemarkTemplate)
 if got!="{{INBOUND}} | {{EMAIL}} | {{PROTOCOL}}" {t.Fatalf("canonical template %q",got)}
 p.RemarkTemplate="{{country}}"
 if err:=ValidateSubscriptionProfile(p);err==nil{t.Fatal("unsupported country placeholder must be rejected")}
}
