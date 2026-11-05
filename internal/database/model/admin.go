package model

// AdminRoot anchors the original owner to an immutable user id. It must never
// be automatically reassigned when another user is deleted or renamed.
type AdminRoot struct {
	ID          int `json:"-" gorm:"primaryKey"`
	OwnerUserID int `json:"ownerUserId" gorm:"not null;uniqueIndex"`
}

func (AdminRoot) TableName() string { return "admin_root" }

// StaffAccount holds role and active state. Credentials remain in users;
// creating a row alone never grants access to existing unscoped panel routes.
type StaffAccount struct {
	UserID     int    `json:"userId" gorm:"primaryKey;not null"`
	Username   string `json:"username" gorm:"uniqueIndex;not null"`
	Role       string `json:"role" gorm:"not null"`
	Enabled    bool   `json:"enabled" gorm:"not null;default:false"`
	CreatedBy  int    `json:"createdBy" gorm:"not null"`
	TOTPSecret string `json:"-" gorm:"column:totp_secret"`
	CreatedAt  int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
	UpdatedAt  int64  `json:"updatedAt" gorm:"autoUpdateTime:milli"`
}

func (StaffAccount) TableName() string { return "staff_accounts" }

type StaffPermission struct {
	UserID    int    `json:"userId" gorm:"primaryKey;not null"`
	Action    string `json:"action" gorm:"primaryKey;not null"`
	DataScope string `json:"scope" gorm:"not null"`
}

func (StaffPermission) TableName() string { return "staff_permissions" }

type StaffInboundAssignment struct {
	UserID    int  `json:"userId" gorm:"primaryKey;not null"`
	InboundID int  `json:"inboundId" gorm:"primaryKey;not null"`
	CanCreate bool `json:"canCreate" gorm:"not null;default:false"`
}

func (StaffInboundAssignment) TableName() string { return "staff_inbound_assignments" }

// StaffSubscriptionProfile is stored independently from global sub settings.
// It MUST NOT be read for a subscription until the client ownership model
// and cache partitioning have been integrated and tested.
type StaffSubscriptionProfile struct {
	UserID              int    `json:"userId" gorm:"primaryKey;not null"`
	Title               string `json:"title"`
	SupportID           string `json:"supportId"`
	SupportURL          string `json:"supportUrl"`
	RemarkTemplate      string `json:"remarkTemplate"`
	ShareLinkTemplate   string `json:"shareLinkTemplate"`
	PageTemplate        string `json:"pageTemplate"`
	SubscriptionBaseURL string `json:"subscriptionBaseUrl"`
}

func (StaffSubscriptionProfile) TableName() string { return "staff_subscription_profiles" }

// StaffClientOwnership is an immutable ownership marker for clients created
// through the isolated staff API. Legacy clients have NO marker and remain
// accessible only to the bootstrap owner.
type StaffClientOwnership struct {
	Email     string `json:"email" gorm:"primaryKey;not null"`
	UserID    int    `json:"userId" gorm:"index;not null"`
	State     string `json:"state" gorm:"not null"`
	CreatedAt int64  `json:"createdAt" gorm:"autoCreateTime:milli"`
}

func (StaffClientOwnership) TableName() string { return "staff_client_ownership" }
