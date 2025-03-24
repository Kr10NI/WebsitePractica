package main

import (
	"encoding/csv"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"io"
	"log"
	"net/http"
	"time"
)

var jwtSecret = []byte("SecretKey4546B_1012Kr41")

type Claims struct {
	UserID uint   `json:"user_id"`
	Role   string `json:"role"`
	jwt.StandardClaims
}

type User struct {
	ID       uint   `gorm:"primaryKey"`
	Username string `gorm:"size:255;unique;not null"`
	Password string `gorm:"size:255;not null"`
	Role     string `gorm:"size:50;not null"` // "admin" or "user"
	Email    string `gorm:"size:255"`
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

var db *gorm.DB

func initDatabase() {
	var err error
	dsn := "KRIONI:45Ps_mySQL46@tcp(185.217.197.125:3306)/websiteDB"
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatal("Failed to connect to database!", err)
	}

	log.Println("Database connected!")
}

func main() {
	initDatabase()
	r := gin.Default()

	r.Use(cors.Default())
	registerRoutes(r)
	r.Run(":8080")
}

func registerRoutes(r *gin.Engine) {
	api := r.Group("/api")
	{
		api.GET("/startups", GetStartups)
		api.GET("/startups/:id", GetStartupByID)
		api.POST("/register", register)
		api.POST("/login", login)
	}
	userGroup := r.Group("/user", authMiddleware("user"))
	{
		userGroup.GET("/startups", GetStartups) // Только для пользователей
	}

	adminGroup := r.Group("/admin", authMiddleware("admin"))
	{
		adminGroup.GET("/startups", GetStartups)            // Получение всех стартапов
		adminGroup.POST("/startups", upsertStartup)         // Создание стартапа
		adminGroup.PUT("/startups/:id", upsertStartup)      // Обновление стартапа
		adminGroup.DELETE("/startups/:id", deleteStartup)   // Удаление стартапа
		adminGroup.POST("/startups/import", importStartups) // Импорт стартапов из файла
	}
}

func GetStartups(c *gin.Context) {
	var startups []Startup
	if err := db.Find(&startups).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to retrieve startups"})
		return
	}
	c.JSON(http.StatusOK, startups)
}

func GetStartupDetails(c *gin.Context) {
	id := c.Param("id")
	var startup Startup
	if err := db.First(&startup, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Startup not found"})
		return
	}
	c.JSON(http.StatusOK, startup)
}

func GetStartupByID(c *gin.Context) {
	id := c.Param("id")
	var startup Startup
	if err := db.Preload("ActivityFields").Preload("Technologies").Preload("Contacts").Preload("Publications").First(&startup, id).Error; err != nil {
		c.JSON(404, gin.H{"error": "Startup not found"})
		return
	}
	c.JSON(200, startup)
}

func GetStartupContacts(c *gin.Context) {
	id := c.Param("id")
	var contact Contact
	if err := db.Where("startup_id = ?", id).First(&contact).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Contacts not found"})
		return
	}
	c.JSON(http.StatusOK, contact)
}

func register(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if user.Role == "" {
		user.Role = "user"
	}

	// Хэширование пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}
	user.Password = string(hashedPassword)

	// Сохранение в базу
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

// Вход пользователя
func login(c *gin.Context) {
	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("username = ?", loginData.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Проверка пароля
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Создание JWT
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: user.ID,
		Role:   user.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func authMiddleware(requiredRole string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if requiredRole != "" && claims.Role != requiredRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}

		c.Set("userID", claims.UserID)
		c.Set("role", claims.Role)
		c.Next()
	}
}

func upsertStartup(c *gin.Context) {
	var startup Startup
	if err := c.ShouldBindJSON(&startup); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if startup.ID == 0 {
		// Создание стартапа
		if err := db.Create(&startup).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create startup"})
			return
		}
	} else {
		// Обновление стартапа
		if err := db.Save(&startup).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update startup"})
			return
		}
	}
	c.JSON(http.StatusOK, startup)
}

// Функция для удаления стартапа
func deleteStartup(c *gin.Context) {
	id := c.Param("id")
	if err := db.Delete(&Startup{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete startup"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Startup deleted successfully"})
}

// Импорт данных из CSV/Excel
func importStartups(c *gin.Context) {
	file, _, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to upload file"})
		return
	}
	defer file.Close()

	startups := parseFile(file)
	if len(startups) > 0 {
		if err := db.Create(&startups).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to import startups"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "Data imported successfully"})
}

func parseFile(file io.Reader) []Startup {
	startups := []Startup{}
	reader := csv.NewReader(file)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		startups = append(startups, Startup{
			Name:        record[0],
			Description: record[1],
		})
	}
	return startups
}
