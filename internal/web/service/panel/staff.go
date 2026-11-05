package panel

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mhsanaei/3x-ui/v3/internal/authz"
	"github.com/mhsanaei/3x-ui/v3/internal/database"
	"github.com/mhsanaei/3x-ui/v3/internal/database/model"
	"github.com/mhsanaei/3x-ui/v3/internal/util/crypto"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// StaffService is the owner-only management backend. Staff routes have a
// separate HTTP allowlist because the inherited 3x-ui API is NOT tenant safe.
type StaffService struct{}

// OwnerID binds first-install owner exactly once. A missing, orphaned anchor
// never grants a staff account ownership.
func (StaffService) OwnerID() (int, error) {
	db := database.GetDB()
	if db == nil {
		return 0, errors.New("database unavailable")
	}
	var root model.AdminRoot
	err := db.Where("id = ?", 1).First(&root).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var count int64
		if e := db.Model(&model.StaffAccount{}).Count(&count).Error; e != nil {
			return 0, e
		}
		if count != 0 {
			return 0, errors.New("missing owner anchor while staff exist")
		}
		var first model.User
		if e := db.Order("id asc").First(&first).Error; e != nil {
			return 0, e
		}
		newRoot := model.AdminRoot{ID: 1, OwnerUserID: first.Id}
		if e := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&newRoot).Error; e != nil {
			return 0, e
		}
		if e := db.Where("id = ?", 1).First(&root).Error; e != nil {
			return 0, e
		}
	} else if err != nil {
		return 0, err
	}
	if root.OwnerUserID <= 0 {
		return 0, errors.New("invalid owner anchor")
	}
	var exists int64
	if e := db.Model(&model.User{}).Where("id = ?", root.OwnerUserID).Count(&exists).Error; e != nil {
		return 0, e
	}
	if exists != 1 {
		return 0, errors.New("owner record missing; refusing reassignment")
	}
	return root.OwnerUserID, nil
}

func (s StaffService) IsOwner(userID int) bool {
	ownerID, err := s.OwnerID()
	return err == nil && userID > 0 && ownerID == userID
}

func (s StaffService) StaffForLogin(userID int) (*model.StaffAccount, error) {
	if userID <= 0 {
		return nil, errors.New("invalid identity")
	}
	rootID, err := s.OwnerID()
	if err != nil {
		return nil, err
	}
	if rootID == userID {
		return nil, nil
	}
	var account model.StaffAccount
	if err := database.GetDB().Where("user_id = ? AND enabled = ?", userID, true).First(&account).Error; err != nil {
		return nil, err
	}
	return &account, nil
}

type StaffCreateInput struct {
	Username string     `json:"username"`
	Password string     `json:"password"`
	Role     authz.Role `json:"role"`
	Enabled  bool       `json:"enabled"`
}

func staffRoleAllowed(role authz.Role) bool {
	return role == authz.RoleSudo || role == authz.RoleAdmin ||
		role == authz.RoleReseller || role == authz.RoleCustom
}

func validStaffUsername(username string) bool {
	if len(username) < 3 || len(username) > 64 {
		return false
	}
	for _, r := range username {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.", r) {
			return false
		}
	}
	return true
}

func validStaffPassword(password string) bool {
	return len(password) >= 12 && len(password) <= 128
}

func (s StaffService) Create(actorID int, in StaffCreateInput) (*model.StaffAccount, error) {
	if !s.IsOwner(actorID) {
		return nil, errors.New("owner permission required")
	}
	username := strings.TrimSpace(in.Username)
	if !validStaffUsername(username) {
		return nil, errors.New("username must be 3–64 characters (ASCII letters, digits, _, -, .)")
	}
	if !validStaffPassword(in.Password) {
		return nil, errors.New("password must have 12–128 bytes")
	}
	if !staffRoleAllowed(in.Role) {
		return nil, errors.New("invalid staff role")
	}
	hash, err := crypto.HashPasswordAsBcrypt(in.Password)
	if err != nil {
		return nil, err
	}
	out := &model.StaffAccount{}
	err = database.GetDB().Transaction(func(tx *gorm.DB) error {
		var count int64
		if e := tx.Model(&model.User{}).Where("LOWER(username) = ?", strings.ToLower(username)).Count(&count).Error; e != nil {
			return e
		}
		if count > 0 {
			return errors.New("username already exists")
		}
		user := model.User{Username: username, Password: hash}
		if e := tx.Create(&user).Error; e != nil {
			return e
		}
		*out = model.StaffAccount{UserID: user.Id, Username: username, Role: string(in.Role), Enabled: in.Enabled, CreatedBy: actorID}
		return tx.Create(out).Error
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

type StaffUpdateInput struct {
	Role     authz.Role `json:"role"`
	Enabled  *bool      `json:"enabled"`
	Password string     `json:"password"`
}

func (s StaffService) Update(actorID, targetID int, in StaffUpdateInput) error {
	if !s.IsOwner(actorID) {
		return errors.New("owner permission required")
	}
	if targetID <= 0 || targetID == actorID {
		return errors.New("cannot change owner")
	}
	if in.Role != "" && !staffRoleAllowed(in.Role) {
		return errors.New("invalid staff role")
	}
	if in.Password != "" && !validStaffPassword(in.Password) {
		return errors.New("password must have 12–128 bytes")
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		var a model.StaffAccount
		if err := tx.Where("user_id = ?", targetID).First(&a).Error; err != nil {
			return err
		}
		changes := map[string]any{}
		if in.Role != "" {
			changes["role"] = string(in.Role)
		}
		if in.Enabled != nil {
			changes["enabled"] = *in.Enabled
		}
		if len(changes) > 0 {
			if err := tx.Model(&a).Updates(changes).Error; err != nil {
				return err
			}
		}
		updateUser := map[string]any{"login_epoch": gorm.Expr("login_epoch + 1")}
		if in.Password != "" {
			hash, err := crypto.HashPasswordAsBcrypt(in.Password)
			if err != nil {
				return err
			}
			updateUser["password"] = hash
		}
		return tx.Model(&model.User{}).Where("id = ?", targetID).Updates(updateUser).Error
	})
}

func (s StaffService) List(actorID int) ([]model.StaffAccount, error) {
	if !s.IsOwner(actorID) {
		return nil, errors.New("owner permission required")
	}
	var users []model.StaffAccount
	err := database.GetDB().Order("created_at desc").Find(&users).Error
	return users, err
}

func (s StaffService) ResolvePrincipal(userID int) (authz.Principal, error) {
	rootID, err := s.OwnerID()
	if err != nil {
		return authz.Principal{}, err
	}
	if userID == rootID {
		return authz.Principal{UserID: userID, Role: authz.RoleOwner, Enabled: true}, nil
	}
	a, err := s.StaffForLogin(userID)
	if err != nil {
		return authz.Principal{}, err
	}
	p := authz.Principal{UserID: a.UserID, Role: authz.Role(a.Role), Enabled: a.Enabled, Overrides: map[authz.Action]authz.DataScope{}}
	var grants []model.StaffPermission
	if err := database.GetDB().Where("user_id = ?", userID).Find(&grants).Error; err != nil {
		return authz.Principal{}, err
	}
	for _, grant := range grants {
		p.Overrides[authz.Action(grant.Action)] = authz.DataScope(grant.DataScope)
	}
	return p, nil
}

func (s StaffService) ListPermissions(actorID, targetID int) ([]model.StaffPermission, error) {
	if !s.IsOwner(actorID) {
		return nil, errors.New("owner permission required")
	}
	var items []model.StaffPermission
	err := database.GetDB().Where("user_id = ?", targetID).Order("action ASC").Find(&items).Error
	return items, err
}

func (s StaffService) SetPermissions(actorID, targetID int, grants []model.StaffPermission) error {
	if !s.IsOwner(actorID) {
		return errors.New("owner permission required")
	}
	if targetID == actorID || targetID <= 0 {
		return errors.New("owner permissions are immutable")
	}
	seen := map[string]struct{}{}
	records := make([]model.StaffPermission, 0, len(grants))
	for _, g := range grants {
		a := authz.Action(g.Action)
		scope := authz.DataScope(g.DataScope)
		if !authz.ValidAction(a) || !authz.ValidScope(scope) ||
			a == authz.OwnerManage || a == authz.AdminsManage || a == authz.PermissionsManage {
			return fmt.Errorf("invalid or reserved permission %q", g.Action)
		}
		if _, ok := seen[g.Action]; ok {
			return errors.New("duplicate permission")
		}
		seen[g.Action] = struct{}{}
		records = append(records, model.StaffPermission{UserID: targetID, Action: g.Action, DataScope: g.DataScope})
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.StaffAccount{}).Where("user_id = ?", targetID).Count(&count).Error; err != nil {
			return err
		}
		if count != 1 {
			return errors.New("staff account not found")
		}
		if err := tx.Where("user_id = ?", targetID).Delete(&model.StaffPermission{}).Error; err != nil {
			return err
		}
		if len(records) > 0 {
			if err := tx.Create(&records).Error; err != nil {
				return err
			}
		}
		return tx.Model(&model.User{}).Where("id = ?", targetID).Update("login_epoch", gorm.Expr("login_epoch + 1")).Error
	})
}

func (s StaffService) SetAssignments(actorID, targetID int, grants []model.StaffInboundAssignment) error {
	if !s.IsOwner(actorID) {
		return errors.New("owner permission required")
	}
	if targetID == actorID || targetID <= 0 {
		return errors.New("cannot assign owner")
	}
	ownerID, err := s.OwnerID()
	if err != nil {
		return err
	}
	seen := map[int]struct{}{}
	records := make([]model.StaffInboundAssignment, 0, len(grants))
	for _, g := range grants {
		if g.InboundID <= 0 {
			return errors.New("invalid inbound id")
		}
		if _, ok := seen[g.InboundID]; ok {
			return errors.New("duplicate inbound assignment")
		}
		seen[g.InboundID] = struct{}{}
		records = append(records, model.StaffInboundAssignment{UserID: targetID, InboundID: g.InboundID, CanCreate: g.CanCreate})
	}
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		var account model.StaffAccount
		if err := tx.Where("user_id = ?", targetID).First(&account).Error; err != nil {
			return err
		}
		if len(records) > 0 {
			ids := make([]int, 0, len(records))
			for _, rec := range records {
				ids = append(ids, rec.InboundID)
			}
			var count int64
			// Only the root owner's physical inbounds are eligible for sharing.
			if err := tx.Model(&model.Inbound{}).Where("id IN ? AND user_id = ?", ids, ownerID).Count(&count).Error; err != nil {
				return err
			}
			if count != int64(len(ids)) {
				return errors.New("one or more inbounds are unavailable or not owned by root")
			}
		}
		if err := tx.Where("user_id = ?", targetID).Delete(&model.StaffInboundAssignment{}).Error; err != nil {
			return err
		}
		if len(records) > 0 {
			return tx.Create(&records).Error
		}
		return nil
	})
}

func (s StaffService) ListAssignments(actorID, targetID int) ([]model.StaffInboundAssignment, error) {
	if !s.IsOwner(actorID) && actorID != targetID {
		return nil, errors.New("permission denied")
	}
	var rows []model.StaffInboundAssignment
	err := database.GetDB().Where("user_id = ?", targetID).Order("inbound_id ASC").Find(&rows).Error
	return rows, err
}

func (s StaffService) GetProfile(actorID, targetID int) (*model.StaffSubscriptionProfile, error) {
	if !s.IsOwner(actorID) && actorID != targetID {
		return nil, errors.New("permission denied")
	}
	var profile model.StaffSubscriptionProfile
	err := database.GetDB().Where("user_id = ?", targetID).First(&profile).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &model.StaffSubscriptionProfile{UserID: targetID}, nil
	}
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func (s StaffService) SetProfile(actorID, targetID int, in model.StaffSubscriptionProfile) error {
	if !s.IsOwner(actorID) && actorID != targetID {
		return errors.New("permission denied")
	}
	if targetID <= 0 {
		return errors.New("invalid target")
	}
	principal, err := s.ResolvePrincipal(actorID)
	if err != nil {
		return err
	}
	if !principal.Allows(authz.TemplatesManage, targetID, false) {
		return errors.New("profile update denied")
	}
	checked := authz.SubscriptionProfile{
		UserID: targetID, Title: in.Title, SupportID: in.SupportID, SupportURL: in.SupportURL,
		RemarkTemplate: in.RemarkTemplate, ShareLinkTemplate: in.ShareLinkTemplate,
		PageTemplate: in.PageTemplate, SubscriptionBaseURL: in.SubscriptionBaseURL,
	}
	if err := authz.ValidateSubscriptionProfile(checked); err != nil {
		return err
	}
	in.UserID = targetID
	return database.GetDB().Transaction(func(tx *gorm.DB) error {
		if targetID != actorID {
			var count int64
			if err := tx.Model(&model.StaffAccount{}).Where("user_id = ?", targetID).Count(&count).Error; err != nil {
				return err
			}
			if count != 1 {
				return errors.New("staff account not found")
			}
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"title", "support_id", "support_url", "remark_template", "share_link_template", "page_template", "subscription_base_url"}),
		}).Create(&in).Error
	})
}
