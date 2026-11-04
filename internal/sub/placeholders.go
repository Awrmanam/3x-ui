package sub

import (
	"errors"
	"net/url"
	"strings"

	"gorm.io/gorm"

	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/logger"
	"github.com/mhsanaei/3x-ui/v3/internal/web/service"
)

type subPlaceholderData struct {
	SubID   string
	Context remarkContext
	HasCtx  bool
	Escape  bool
}

type renderedSubMetadata struct {
	Title      string
	SupportURL string
	ProfileURL string
	Announce   string
}

func renderSubPlaceholders(value string, data subPlaceholderData) string {
	if value == "" || !strings.Contains(value, "{") {
		return value
	}

	ctx := data.Context
	if !data.HasCtx {
		ctx = remarkContext{
			client: model.Client{
				SubID: data.SubID,
			},
		}
	}
	if ctx.client.SubID == "" {
		ctx.client.SubID = data.SubID
	}
	return strings.TrimSpace(expandSubMetadataVars(value, ctx, data.Escape))
}

var subMetadataTokens = map[string]bool{
	"EMAIL":       true,
	"ID":          true,
	"SHORT_ID":    true,
	"TELEGRAM_ID": true,
	"SUB_ID":      true,
}

func expandSubMetadataVars(template string, ctx remarkContext, escape bool) string {
	return remarkVarRe.ReplaceAllStringFunc(template, func(match string) string {
		token := match[2 : len(match)-2]
		if !subMetadataTokens[token] {
			return match
		}
		value := remarkVarValue(token, ctx)
		if escape {
			return url.QueryEscape(value)
		}
		return value
	})
}

func subMetadataUsesPlaceholders(values ...string) bool {
	for _, value := range values {
		if strings.Contains(value, "{") {
			return true
		}
	}
	return false
}

func (a *SUBController) metadataForSubRequest(getSubReq func() *SubService, subID, builtinURL string) renderedSubMetadata {
	profileURL := ""
	switch a.subProfileMode {
	case service.SubProfileModeBuiltin:
		profileURL = builtinURL
	case service.SubProfileModeCustom:
		profileURL = strings.TrimSpace(a.subProfileUrl)
	}
	var context remarkContext
	var hasContext bool
	if subMetadataUsesPlaceholders(a.subTitle, a.subSupportUrl, profileURL, a.subAnnounce) {
		var err error
		subReq := getSubReq()
		context, hasContext, err = subReq.subscriptionTemplateContextBySubID(subID)
		if err != nil {
			logger.Warning("sub: load template contexts for subscription metadata:", err)
		}
	}
	// Disabled modes ignore the retained custom URL and never fall back to the request URL.
	profileURL = renderSubPlaceholders(profileURL, subPlaceholderData{SubID: subID, Context: context, HasCtx: hasContext, Escape: true})
	data := subPlaceholderData{SubID: subID, Context: context, HasCtx: hasContext}
	metadata := renderedSubMetadata{
		Title:      renderSubPlaceholders(a.subTitle, data),
		SupportURL: renderSubPlaceholders(a.subSupportUrl, subPlaceholderData{SubID: subID, Context: context, HasCtx: hasContext, Escape: true}),
		ProfileURL: profileURL,
		Announce:   renderSubPlaceholders(a.subAnnounce, data),
	}
	// Resolve the reseller from the subscriber's *persisted* email ownership,
	// never from a caller-controlled query string or host header. Other users'
	// subscriptions continue to use the original global settings.
	if override, ok := staffSubscriptionMetadata(subID); ok {
		if override.Title != "" {
			metadata.Title = override.Title
		}
		if override.SupportURL != "" {
			metadata.SupportURL = override.SupportURL
		} else if override.SupportID != "" {
			metadata.SupportURL = "https://t.me/" + strings.TrimPrefix(override.SupportID, "@")
		}
	}
	return metadata
}

// staffSubscriptionMetadata does not cache a cross-tenant subscription
// profile; each request is resolved by the unique subscriber's stored email.
func staffSubscriptionMetadata(subID string) (model.StaffSubscriptionProfile, bool) {
	if strings.TrimSpace(subID) == "" {
		return model.StaffSubscriptionProfile{}, false
	}
	db := database.GetDB()
	if db == nil {
		return model.StaffSubscriptionProfile{}, false
	}
	var profile model.StaffSubscriptionProfile
	err := db.Model(&model.StaffSubscriptionProfile{}).
		Joins("JOIN staff_client_ownership AS owner ON owner.user_id = staff_subscription_profiles.user_id").
		Joins("JOIN clients ON LOWER(clients.email) = owner.email").
		Where("clients.sub_id = ? AND owner.state = ?", subID, "active").
		First(&profile).Error
	return profile, err == nil
}

func (s *SubService) subscriptionTemplateContextBySubID(subID string) (remarkContext, bool, error) {
	if subID == "" {
		return remarkContext{}, false, nil
	}
	var rec model.ClientRecord
	err := database.GetDB().Where("sub_id = ?", subID).Order("id ASC").First(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return remarkContext{}, false, nil
	}
	if err != nil {
		return remarkContext{}, false, err
	}
	return remarkContext{client: *rec.ToClient()}, true, nil
}
