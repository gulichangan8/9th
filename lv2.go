package main

import (
	"crypto/hmac"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"
)

type Cookie struct {
	sid    string
	domain string
	maxAge int64
}

type SessionFromMemory struct {
	sid    string
	lock   sync.Mutex
	maxAge int64
	data   string
}

func Set(si *SessionFromMemory, value string) int64 {
	si.lock.Lock()
	defer si.lock.Unlock()
	si.data = value
	si.maxAge = 1800*60 + time.Now().Unix()
	return si.maxAge
}

func GetId(si *SessionFromMemory, dB *sql.DB) string {
	r := rand.New(rand.NewSource(time.Now().Unix())).Intn(999)
	si.sid = Hmac(strconv.Itoa(r), si.data)
	_, err := dB.Exec("insert into session (sid,date,ddl) value (?,?,?)",
		si.sid, si.data, si.maxAge)
	if err != nil {
		log.Println(err)
	}
	return si.sid
}

func Hmac(key, date string) string {
	hash := hmac.New(md5.New, []byte(key))
	hash.Write([]byte(date))
	return hex.EncodeToString(hash.Sum(nil))
}

func outDate(si *SessionFromMemory, sid string, cookie Cookie, user string, dB *sql.DB) bool {
	row := dB.QueryRow("select * from session where sid=?", sid)
	err := row.Scan(&si.sid, &si.data, &si.maxAge)
	if err != nil {
		return false
	}
	if si.maxAge <= time.Now().Unix() {
		_, err := dB.Exec("delete from session where sid=?", sid)
		if err != nil {
			log.Println(err)
		}
		cookie.maxAge = Set(si, user)
		cookie.sid = GetId(si, dB)
		return false
	} else {
		return true
	}
}

func CheckUser(si *SessionFromMemory, user string, dB *sql.DB) bool {
	rows, err := dB.Query("select * from session")
	if err != nil {
		log.Println(err)
	}
	for rows.Next() {
		err := rows.Scan(&si.sid, &si.data, &si.maxAge)
		if err != nil {
			log.Println(err)
		}
		if user == si.data {
			return false
		}
	}
	return true
}

func main() {
	dB, err := sql.Open("mysql",
		"root:040818@tcp(127.0.0.1:3306)/secret?charset=utf8mb4&parseTime=True&loc=Local")
	if err != nil {
		return
	}
	r := gin.Default()
	r.Use(CorsHandler(dB))
	r.GET("/hello", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"response": "hello world",
		})
	})
	err = r.Run()
	if err != nil {
		return
	}
}

func CorsHandler(dB *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method
		origin := c.Request.Header.Get("Origin") //请求头部
		domain := c.Request.Host
		user := c.PostForm("username")
		var cookie Cookie
		cookie.domain = domain
		var si SessionFromMemory
		sid, err := c.Cookie("sid")
		if err != nil {
			ok := CheckUser(&si, user, dB)
			if ok == false {
				c.JSON(200, "用户已存在")
				c.Abort()
			} else {
				cookie.maxAge = Set(&si, user)
				cookie.sid = GetId(&si, dB)
			}
		} else {
			ok := outDate(&si, sid, cookie, user, dB)
			if ok == false {
				c.JSON(404, "未找到用户")
				c.Abort()
			}
		}
		if origin != "" {
			//接收客户端发送的origin （重要！）
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			//服务器支持的所有跨域请求的方法
			c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE,UPDATE")
			//允许跨域设置可以返回其他子段，可以自定义字段
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Length, X-CSRF-Token, Token,session")
			// 允许浏览器（客户端）可以解析的头部 （重要）
			c.Header("Access-Control-Expose-Headers", "Content-Length, Access-Control-Allow-Origin, Access-Control-Allow-Headers")
			//设置缓存时间
			c.Header("Access-Control-Max-Age", "172800")
			//允许客户端传递校验信息比如 cookie (重要)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.SetCookie("cookie", "sid="+cookie.sid, int(cookie.maxAge), "/", cookie.domain, false, true)
		}

		//允许类型校验
		if method == "OPTIONS" {
			c.JSON(http.StatusOK, "ok!")
		}

		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic info is: %v", err)
			}
		}()

		c.Next()
	}
}
