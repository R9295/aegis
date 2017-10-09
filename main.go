package main

import(
	"fmt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"time"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"crypto/rand"
	"encoding/hex"

)


//function to generate random bytes,securely, for a key
//from https://gist.github.com/shahaya/635a644089868a51eccd6ae22b2eb800
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

//hash bcrypt password
func Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

//Verify bcrypt password
func VerifyHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}


func main() {
	b, err := ioutil.ReadFile("private.txt")
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")
	session, err := mgo.Dial(string(b))
	db_user := session.DB("aegis").C("users")
	//db_note := session.DB("aegis").C("notes")
    if err != nil {
        panic(err)
    }
    defer session.Close()

	//ROutes
	route := router.Group("/")
	{

		//landing page
		route.GET("/",func(c *gin.Context){
			c.HTML(http.StatusOK, "landing.tmpl", gin.H{
				"login":"login",
				})
			})


		//get key
		route.POST("/get_key",func(c *gin.Context){
			gen_key, err := GenerateRandomBytes(32)
			if err != nil {
				fmt.Println(err) 
			}
			key_hash,err := Hash(string(gen_key))
			if err != nil{
				fmt.Println(err)
			}

			key := hex.EncodeToString(gen_key)

			type response struct{
				key string
				key_hash string
			}
			
			c.JSON(200,gin.H{
				"key":key,
				"key_hash":string(key_hash),
				})


			
			})
		//login
		route.GET("/login",func(c *gin.Context){
			c.HTML(http.StatusOK, "login.tmpl", gin.H{
				"login":"login",
				})
			})
		route.POST("/login",func(c *gin.Context){
			//get JSON data
			var data struct {
				email string `json:"email" binding:"required"`
				password string `json:"password" binding:"required"`
				imageHash string `json:"img_hash" binding:"required"`
			}
			//Check if user exists


			fmt.Println(data)

			c.JSON(200,gin.H{
				"message":"pong",
				})
			})

		//signup GET
		route.GET("/signup",func(c *gin.Context){
			c.HTML(http.StatusOK,"signup.tmpl", gin.H{
				})
			})

		//signup POST
		route.POST("/signup",func(c *gin.Context){
			//get the date today
			t := time.Now()
			start_date := t.Format("2006-01-02")
			
			//construct userdata type
			type UserData struct {
				id        bson.ObjectId `bson:_id,omitempty`	
				Email     string `json:"email" binding:"required"` 		
				Password  string `json:"password" binding:"required"` 		
				Acc_Type   string `json:"acc_type" binding:"required"` 	
				Key_Hash   string `json:"key_hash" binding:"required"` 		
				Start_Date string 
				End_Date   string

			}

			var data UserData
			password,err := Hash(data.Password)
			if err != nil{
				fmt.Println(err)
			}
			c.BindJSON(&data)
			db_user.Insert(UserData{
				Email: data.Email,
				Password: string(password),
				Acc_Type: data.Acc_Type,
				Key_Hash: data.Key_Hash,
				Start_Date: start_date,
				End_Date: "ASD" ,
				})			
			})

		//view all notes
		route.POST("/view_all_notes/",func(c *gin.Context) {
			c.JSON(200,gin.H{
				"message":"pong",
				})
			})


		//add note
		route.GET("/add_note", func(c *gin.Context) {
			c.HTML(http.StatusOK, "add_note.tmpl", gin.H{
				"login":"login",
				})
			})
		
		
		route.POST("/add_note", func(c *gin.Context) {
				c.JSON(200,gin.H{
				"message":"asd",
				})
			})

		//view single note
		route.GET("/view_note/:username/:note_id", func(c *gin.Context) {
			username := c.Param("username")
			note_id := c.Param("note_id")
			c.HTML(http.StatusOK,"view_single_note.tmpl",gin.H{
					"username":username,
					"note_id":note_id,
				})
			
		})


		
	
	router.Run(":5000")
	
}
}


