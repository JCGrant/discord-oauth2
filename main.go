package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"github.com/joho/godotenv"
)

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint   `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("loading .env file failed: %s", err)
	}
	clientID := os.Getenv("DISCORD_CLIENT_ID")
	clientSecret := os.Getenv("DISCORD_CLIENT_SECRET")
	redirectURL := os.Getenv("DISCORD_REDIRECT_URL")

	r := gin.Default()
	r.LoadHTMLGlob("templates/**/*")
	store := cookie.NewStore([]byte("secret"))
	store.Options(sessions.Options{Path: "/", MaxAge: 60 * 60 * 24})
	r.Use(sessions.Sessions("session", store))
	client := &http.Client{}

	r.GET("/login", func(c *gin.Context) {
		session := sessions.Default(c)
		if session.Get("accessToken") != nil {
			c.Redirect(http.StatusFound, "/user")
		}
		c.HTML(http.StatusOK, "login.html", gin.H{
			"title": "Login With Discord",
		})
	})

	r.GET("/auth/discord/redirect", func(c *gin.Context) {
		session := sessions.Default(c)
		code := c.Request.URL.Query().Get("code")
		values := url.Values{}
		values.Add("client_id", clientID)
		values.Add("client_secret", clientSecret)
		values.Add("grant_type", "authorization_code")
		values.Add("code", code)
		values.Add("redirect_uri", redirectURL)
		req, err := http.NewRequest("POST",
			"https://discord.com/api/v10/oauth2/token",
			strings.NewReader(values.Encode()),
		)
		if err != nil {
			log.Fatalf("creating access token request failed: %s", err)
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("requesting access token failed: %s", err)
		}
		var response AccessTokenResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			log.Fatalf("decoding access token response failed: %s", err)
		}
		session.Set("accessToken", response.AccessToken)
		session.Set("refreshToken", response.RefreshToken)
		err = session.Save()
		if err != nil {
			log.Fatalf("saving access token to session failed: %s", err)
		}
		c.Redirect(http.StatusFound, "/user")
	})

	r.GET("/logout", func(c *gin.Context) {
		session := sessions.Default(c)
		session.Delete("accessToken")
		session.Delete("refreshToken")
		session.Save()
		c.Redirect(http.StatusSeeOther, "/login")
	})

	r.GET("/user", func(c *gin.Context) {
		session := sessions.Default(c)
		accessToken := session.Get("accessToken")
		if accessToken == nil {
			c.Redirect(http.StatusFound, "/login")
		}
		req, err := http.NewRequest("GET", "https://discord.com/api/v10/users/@me", nil)
		if err != nil {
			log.Fatalf("creating user request failed: %s", err)
		}
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("requesting user failed: %s", err)
		}
		var user User
		err = json.NewDecoder(resp.Body).Decode(&user)
		if err != nil {
			log.Fatalf("decoding user response failed: %s", err)
		}
		if user.ID == "" {
			c.Redirect(http.StatusFound, "/login")
		}
		c.HTML(http.StatusOK, "user.html", gin.H{
			"title": fmt.Sprintf("%s's page", user.Username),
			"user":  user,
		})
	})

	r.Run()
}
