package main

import(
	"fmt"
	"gopkg.in/mgo.v2" //mongo driver
	"gopkg.in/mgo.v2/bson" //generate object ids
	"io/ioutil"
	"io"
	"time"
	"github.com/rs/xid" //UID generation
	"github.com/gin-gonic/gin" //webserver
	"golang.org/x/crypto/bcrypt" //password hashing
	"net/http"
	"crypto/rand"
 	"golang.org/x/crypto/nacl/secretbox" 
	"encoding/hex"
	"github.com/go-redis/redis"

)


//function to GenerateRandomBytes,securely, for a key
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

type User struct{
	id 		   bson.ObjectId
	Email  	   string
	Password   string
	AccType   string
	KeyHash   string 
	StartDate string
	EndDate   string 
}

func main() {
	b, err := ioutil.ReadFile("private.txt")
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")
	session, err := mgo.Dial(string(b))
	db_user := session.DB("aegis").C("users")
	//db_note := session.DB("aegis").C("notes")

	redis_session := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	pong, err := redis_session.Ping().Result()
	fmt.Println(pong, err)
    
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
			key_hash,err := bcrypt.GenerateFromPassword([]byte(string(gen_key)), bcrypt.DefaultCost)
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
			type LoginData struct {
				Email string `json:"email" binding:"required"`
				Password string `json:"password" binding:"required"`
				Key string `json:"key" binding:"required"`
			}

			//Check if user exists
			var data LoginData
			c.BindJSON(&data)
			
			user, err := db_user.Find(bson.M{"email":data.Email}).Count()
			if err != nil{
				panic(err)
			}

			//if exists
			if user == 1{
				result := User{}
				err := db_user.Find(bson.M{"email":data.Email}).One(&result)
				if err != nil{
					panic(err)
				}
				//check if passwords match.
				hash := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(data.Password))
				if hash != nil{
				c.JSON(200,gin.H{
					"err":"wrong_user_pass",
					})	
				} else {
					//if passwords match, see if their keys match.
					key,err := hex.DecodeString(data.Key)
					if err != nil{
						panic(err)
					}
					hash := bcrypt.CompareHashAndPassword([]byte(result.KeyHash), []byte(key))
					if hash != nil{
						c.JSON(200,gin.H{
							"err":"wrong_key",
							})
					} else{
						//login successful. 

						//generate UID
						uid := xid.New().String()

						//create session key to encrypt the key in
						gen_key, err := GenerateRandomBytes(32)
						if err != nil{
							panic(err)
						}
						//Generate random nonce
						var nonce [24]byte
						if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
    					panic(err)
						}

						//changing type so that the reads it
						var secretkey [32]byte
						copy(secretkey[:],gen_key)

						// encrypt the key
						encrypted_key := secretbox.Seal(nonce[:], []byte(data.Key), &nonce, &secretkey)
						key := hex.EncodeToString(encrypted_key)
						session_data := make(map[int]string)
						session_data[0] = data.Email
						session_data[1] = hex.EncodeToString(gen_key)
						session_data[2] = nonce
						fmt.Println(session_data)

						//redis_session.HMSet(uid,session_data)
						
						c.JSON(200,gin.H{
							"key" : key,
							"id": uid,
							})
					}

				}
				
				

			}

			//if not found
			if user == 0{
				c.JSON(200,gin.H{
					"err":"wrong_user_pass",
					})	
			}

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
			StartDate := t.Format("2006-01-02")
			
			//construct userdata type
			type UserData struct {
				id        bson.ObjectId `bson:_id,omitempty`	
				Email     string `json:"email" binding:"required"` 		
				Password  string  `json:"password" binding:"required"` 		
				AccType   string `json:"acc_type" binding:"required"` 	
				KeyHash   string `json:"key_hash" binding:"required"` 		
				StartDate string 
				EndDate   string

			}

			var data UserData
			c.BindJSON(&data)
			password, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)

			if err != nil{
				fmt.Println(err)
			}
			
			db_user.Insert(UserData{
				Email: data.Email,
				Password: string(password),
				AccType: data.AccType,
				KeyHash: data.KeyHash,
				StartDate: StartDate,
				EndDate: "ASD" ,
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
		route.GET("/view_note/:username/:noteid", func(c *gin.Context) {
			username := c.Param("username")
			noteid := c.Param("noteid")
			c.HTML(http.StatusOK,"view_single_note.tmpl",gin.H{
					"username":username,
					"noteid":noteid,
				})
			
		})


		
	
	router.Run(":5000")
	
}
}


