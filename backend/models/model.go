package models

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"size:255;unique;not null"`
	Password string `gorm:"size:255;not null"`
	Role     string `gorm:"size:50;not null"` // "admin" or "user"
}

type Startup struct {
	ID             uint   `gorm:"primaryKey"`
	Name           string `gorm:"size:255;not null"`
	Description    string
	BatchNumber    int
	ReleaseYear    int
	TrackerName    string
	ActivityFields []ActivityField `gorm:"many2many:startup_activity_fields"`
	Technologies   []Technology    `gorm:"many2many:startup_technologies"`
	Contacts       Contact         `gorm:"foreignKey:StartupID"`
	Publications   []Publication   `gorm:"foreignKey:StartupID"`
}

type ActivityField struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"size:255;unique;not null"`
}

type Technology struct {
	ID   uint   `gorm:"primaryKey"`
	Name string `gorm:"size:255;unique;not null"`
}

type Contact struct {
	ID        uint   `gorm:"primaryKey"`
	StartupID uint   `gorm:"not null"`
	Phone     string `gorm:"size:20"`
	Email     string `gorm:"size:255"`
	Telegram  string `gorm:"size:255"`
}

type Publication struct {
	ID        uint   `gorm:"primaryKey"`
	StartupID uint   `gorm:"not null"`
	URL       string `gorm:"size:255;not null"`
}
