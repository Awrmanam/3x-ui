package authz

import (
 "errors"
 "fmt"
 "net/url"
 "regexp"
 "strings"
 "unicode/utf8"
)

// SubscriptionProfile belongs to exactly one admin. The subscription service
// must resolve its owner from the client record, never a request parameter.
// This value object does not yet alter the production subscription pipeline.
type SubscriptionProfile struct {
 UserID int
 Title string
 SupportID string
 SupportURL string
 RemarkTemplate string
 ShareLinkTemplate string
 PageTemplate string
 SubscriptionBaseURL string
}

// Supported placeholders are intentionally narrow. Raw Go/HTML templates from
// untrusted admins must never be evaluated against host/application state.
var allowedRemarkPlaceholders = map[string]struct{}{
 "client":{}, "server":{}, "country":{}, "protocol":{}, "remark":{},
}
var placeholderRE = regexp.MustCompile(`\{\{([a-zA-Z][a-zA-Z0-9_]*)\}\}`)
var supportIDRE = regexp.MustCompile(`^[a-zA-Z0-9_]{5,32}$`)
var templateNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func validatePlainText(value, field string, maxRunes int) error {
 if utf8.RuneCountInString(value)>maxRunes || strings.ContainsAny(value,"\x00\r\n") {
  return fmt.Errorf("%s has invalid length or control characters",field)
 }
 return nil
}

func validateHTTPSURL(raw, field string) error {
 if raw=="" {return nil}
 u,err:=url.Parse(raw)
 if err!=nil || u==nil || u.Scheme!="https" || u.Hostname()=="" || u.User!=nil || u.Fragment!="" || u.Opaque!="" {
  return fmt.Errorf("%s must be an absolute HTTPS URL without credentials or fragment",field)
 }
 if strings.ContainsAny(u.Hostname()," \t\r\n") {
  return fmt.Errorf("%s contains an invalid hostname",field)
 }
 return nil
}

func validateRemarkTemplate(value string) error {
 if err:=validatePlainText(value,"remark template",256);err!=nil{return err}
 cleaned:=placeholderRE.ReplaceAllStringFunc(value,func(s string)string{return ""})
 if strings.Contains(cleaned,"{{") || strings.Contains(cleaned,"}}") {
  return errors.New("remark template contains unknown template syntax")
 }
 for _,match:=range placeholderRE.FindAllStringSubmatch(value,-1) {
  if _,ok:=allowedRemarkPlaceholders[match[1]];!ok {
   return fmt.Errorf("remark template placeholder %q is not allowed",match[1])
  }
 }
 return nil
}

// ValidateSubscriptionProfile rejects unsafe profile values before persistence.
// URL/domain ownership verification and tenant-scoped template rendering still
// require integration in the owner-only management and public sub handlers.
func ValidateSubscriptionProfile(p SubscriptionProfile) error {
 if p.UserID<=0{return errors.New("subscription profile must have an owner")}
 if err:=validatePlainText(p.Title,"title",120);err!=nil{return err}
 normalizedSupportID:=strings.TrimPrefix(p.SupportID,"@")
 if err:=validatePlainText(normalizedSupportID,"support ID",32);err!=nil{return err}
 if p.SupportID!="" && !supportIDRE.MatchString(normalizedSupportID) {
  return errors.New("support ID must be a Telegram username of 5–32 characters")
 }
 if err:=validateHTTPSURL(p.SupportURL,"support URL");err!=nil{return err}
 if err:=validateHTTPSURL(p.SubscriptionBaseURL,"subscription base URL");err!=nil{return err}
 if err:=validateRemarkTemplate(p.RemarkTemplate);err!=nil{return err}
 // Templates are static administrator-controlled names, not file paths.
 for _,entry:=range []struct{name,value string}{
  {"share-link template",p.ShareLinkTemplate},{"subscription-page template",p.PageTemplate},
 }{
  if entry.value!="" && !templateNameRE.MatchString(entry.value) {
   return fmt.Errorf("%s must be a registered template name, not a path",entry.name)
  }
 }
 return nil
}

// CanEditSubscriptionProfile applies the same persisted resource ownership
// decision as any other action. In production, load the target profile owner
// from the DB before calling this function.
func (p Principal) CanEditSubscriptionProfile(profileOwnerID int) bool {
 return p.Allows(TemplatesManage,profileOwnerID,false)
}
