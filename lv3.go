package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var allow = map[string]string{
	"guli":    "20040818",
	"changan": "20040329",
}

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type payload struct {
	Aud string `json:"aud"`
	Iat string `json:"iat"`
	Exp string `json:"exp"`
	Sub string `json:"sub"`
}

func Check(c *gin.Context, h Header, p payload, key string) bool {
	username := c.PostForm("username")
	password := c.PostForm("password")
	if allow[username] == password {
		h.Alg = "HS256"
		h.Typ = "JWT"
		p.Aud = username
		p.Iat = time.Now().Format("2006-01-02 15:04:05") + " " + strconv.FormatInt(time.Now().Unix(), 10)
		p.Exp = time.Unix(time.Now().Unix()+24*60*60*1000, 0).Format("2006-01-02 15:04:05")
		p.Sub = "Login"
		date := base64.URLEncoding.EncodeToString([]byte(h.Alg+" "+h.Typ)) + "." +
			base64.URLEncoding.EncodeToString([]byte(p.Aud+" "+p.Iat+" "+p.Exp+" "+p.Sub))
		signature := HmacSha(key, date)
		j := date + " " + signature
		c.JSON(200, gin.H{
			"JWT": j,
		})
		return true
	}
	return false
}

func HmacSha(key, date string) string {
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(date))
	return hex.EncodeToString(hash.Sum(nil))
}

func VerifyHmac(JWT string, date string, key string) bool {
	jwt := []byte(JWT)
	now := HmacSha(date, key)
	return hmac.Equal(jwt, []byte(now))
}

func main() {
	r := gin.Default()
	r.Use(cors())
	r.GET("/login", func(c *gin.Context) {
		c.JSON(200, "登陆成功！")
	})
	err := r.Run()
	if err != nil {
		return
	}
}

func cors() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin")
		var h Header
		var p payload
		key := "gulichangan"
		ok := Check(c, h, p, key)
		if !ok {
			jwt := c.Request.Header.Get("Authorization")
			jwts := strings.Split(jwt, ".")
			header := jwts[0]
			headers := strings.Split(header, " ")
			h.Alg = headers[0]
			h.Typ = headers[1]
			payload := jwts[1]
			signature := jwts[2]
			payloads := strings.Split(payload, " ")
			p.Aud = payloads[0]
			p.Iat = payloads[1]
			p.Exp = payloads[2]
			p.Sub = payloads[3]
			date := base64.URLEncoding.EncodeToString([]byte(h.Alg+" "+h.Typ)) + "." +
				base64.URLEncoding.EncodeToString([]byte(p.Aud+" "+p.Iat+" "+p.Exp+" "+p.Sub))
			exps := strings.Split(p.Iat, " ")
			e, _ := strconv.Atoi(exps[1])
			if e+24*60*60*1000 <= int(time.Now().Unix()) {
				c.JSON(404, gin.H{
					"JWT": "已过期",
				})
				c.Abort()
			}
			ok = VerifyHmac(signature, date, key)
			if !ok {
				c.JSON(404, gin.H{
					"JWT": "验证失败",
				})
				c.Abort()
			}
		}
		// 允许所有header
		var headerKeys []string
		for k, _ := range c.Request.Header {
			headerKeys = append(headerKeys, k)
		}
		headerStr := strings.Join(headerKeys, ", ")
		if headerStr != "" {
			headerStr = fmt.Sprintf("access-control-allow-origin, access-control-allow-headers, %s", headerStr)
		} else {
			headerStr = "access-control-allow-origin, access-control-allow-headers"
		}

		if origin != "" {
			c.Header("Access-Control-Allow-Origin", "*")                                       // 这是允许访问所有的域,也可以指定某几个特定的域
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE,UPDATE") //服务器支持的所有跨域请求的方法,为了避免浏览次请求的多次'预检'请求
			// header的类型
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Length, X-CSRF-Token, Token,session,X_Requested_With,Accept, Origin, Host, Connection, Accept-Encoding, Accept-Language,DNT, X-CustomHeader, Keep-Alive, User-Agent, X-Requested-With, If-Modified-Since, Cache-Control, Content-Type, Pragma") //允许跨域设置可以返回其他子段
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers,Cache-Control,Content-Language,Content-Type,Expires,Last-Modified,Pragma,FooBar")                                                                                                           // 跨域关键设置 让浏览器可以解析
			c.Header("Access-Control-Max-Age", "172800")                                                                                                                                                                                                                                                                     // 缓存请求信息 单位为秒
			c.Header("Access-Control-Allow-Credentials", "false")                                                                                                                                                                                                                                                            // 跨域请求是否需要带cookie信息 默认设置为true
		}

		if method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
