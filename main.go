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
	"net/url"
	"crypto/rand"
 	"golang.org/x/crypto/nacl/secretbox" 
	"encoding/hex"
	"github.com/fzzy/radix/redis"
	

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

type NoteData struct{
	id        bson.ObjectId 
	Title	  string 	 	
	Note      string 	
	NoteType  string 	
	WhenMade  string 	
	User      string  	
	Tag		  string  	   
}


func main() {
	b, err := ioutil.ReadFile("private.txt")
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")
	session, err := mgo.Dial(string(b))
	dbUser := session.DB("aegis").C("users")
	dbNote := session.DB("aegis").C("notes")
	redis_session,err := redis.DialTimeout("tcp", "127.0.0.1:6379", time.Duration(10)*time.Second)
	if err != nil{
		panic(err)
	}

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
			
			user, err := dbUser.Find(bson.M{"email":data.Email}).Count()
			if err != nil{
				panic(err)
			}

			//if exists
			if user == 1{
				result := User{}
				err := dbUser.Find(bson.M{"email":data.Email}).One(&result)
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

						// encrypt the user key
						encrypted_key := secretbox.Seal(nonce[:], []byte(data.Key), &nonce, &secretkey)
						
						key := hex.EncodeToString(encrypted_key)
						session := map[string]string{
							"key":hex.EncodeToString(gen_key),
							"user":result.Email,
						}
						insert := redis_session.Cmd("hmset",uid,session)
						if insert != nil{
							fmt.Println(insert)
						}
						
						c.JSON(200,gin.H{
							"response":"succ",
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
			
			dbUser.Insert(UserData{
				Email: data.Email,
				Password: string(password),
				AccType: data.AccType,
				KeyHash: data.KeyHash,
				StartDate: StartDate,
				EndDate: "ASD" ,
				})			
			})

		//view all notes
		route.GET("/view_notes",func(c *gin.Context) {
			//get ID
			id_cookie, err := c.Request.Cookie("id")
			if err != nil{
				fmt.Println(err)
			}
			id_cookie_val,err := url.QueryUnescape(id_cookie.Value)
			if err != nil{
				panic(err)
			}

			//checksession
			asd := redis_session.Cmd("hmget",id_cookie_val,"user").String()
			if asd == "[ <nil> ]"{
				//session doesnt exist
				c.JSON(403,gin.H{
				"status":"unauthorized,fuck_off",
				})
			} else{

				//session exists
				
				//get user
				dict,err := redis_session.Cmd("hgetall",id_cookie_val).Hash()
				if err != nil{
					panic(err)
				}

				var notes []NoteData
				iter := dbNote.Find(bson.M{"user": dict["user"]}).Sort("-timesptamp").All(&notes)
				//all := iter.All(&notes) 

				if iter != nil {
					fmt.Println("asd")
				}
				//get client key from cookie
				keyInCookie, err := c.Request.Cookie("key")
				keyVal,err := url.QueryUnescape(keyInCookie.Value)
				if err != nil{
					panic(err)
				}
				//Decode Client Key
				encryptedKey,err := hex.DecodeString(keyVal)
				if err != nil{
					panic(err)
				}
				//copy the first 24 bytes of ciphertext for the nonce
				var sessionNonce [24]byte
				copy(sessionNonce[:],encryptedKey[:24])

				//decode session key's hex string 
				sessionkey,err := hex.DecodeString(dict["key"])
				if err != nil{
					panic(err)
				}

				var sessionKey [32]byte
				copy(sessionKey[:],sessionkey)

				//decrypt client key with session key
				clientkey,ok := secretbox.Open(nil,encryptedKey[24:],&sessionNonce,&sessionKey) 
				if !ok {
					panic(err)
				} 
				//convert client key into [32]byte
				var clientKey [32]byte
				copy(clientKey[:],clientkey)
				var decryptedNotes []NoteData

				//for all notes
				for k,v := range notes{
					fmt.Println(k)
					//decode the encrypted note
					decode,err := hex.DecodeString(v.Title)
					if err != nil{
						fmt.Println(err)
					}

					//get the nonce from the first 24 bytes
					var note_nonce [24]byte
					copy(note_nonce[:],decode[:24])
					
					//decrypt the title
					box,ok := secretbox.Open(nil,decode[24:],&note_nonce,&clientKey)
					if !ok{
						fmt.Println(err)
					} 

					//set decrypted values to send to browser
					v.Note = string(box)
					asd := NoteData{
						id:v.id,
						Title:string(box),
						Note:v.Note,
						NoteType:v.NoteType,
						WhenMade:v.WhenMade,
						User:v.User,
						Tag:v.Tag,
					}
					add_to_list := append(decryptedNotes,asd)
					if add_to_list == nil{
						panic("cant append")
					}
					
				}
				c.HTML(http.StatusOK,"view_notes.tmpl",gin.H{
					"notes":decryptedNotes,
					"user":dict["user"],

				})

				
			}
			})

		//add note
		route.GET("/add_note", func(c *gin.Context) {
			//get ID
			id_cookie, err := c.Request.Cookie("id")
			if err != nil{
				fmt.Println(err)
			}
			id_cookie_val,err := url.QueryUnescape(id_cookie.Value)
			if err != nil{
				panic(err)
			}

			//checksession
			asd := redis_session.Cmd("hmget",id_cookie_val,"user").String()
			if asd == "[ <nil> ]"{
				//session doesnt exist
				c.JSON(403,gin.H{
				"status":"unauthorized,fuck_off",
				})
			} else{
			c.HTML(http.StatusOK, "add_note.tmpl", gin.H{
				"login":"login",
				})
			}
	})
		
		
		route.POST("/add_note", func(c *gin.Context) {
			//get ID
			id_cookie, err := c.Request.Cookie("id")
			if err != nil{
				fmt.Println(err)
			}
			id_cookie_val,err := url.QueryUnescape(id_cookie.Value)
			if err != nil{
				panic(err)
			}

			//checksession
			asd := redis_session.Cmd("hmget",id_cookie_val,"user").String()
			if asd == "[ <nil> ]"{
				//session doesnt exist
				c.JSON(403,gin.H{
				"status":"unauthorized,fuck_off",
				})
			} else{
				//session exists.
				type NoteData struct{
				id        bson.ObjectId `bson:_id,omitempty`
				Title	  string 	`json:"title" binding:"required"`
				Note      string 	`json:"note" binding:"required"`
				NoteType 	  string 	`json:"type" binding:"required"` 
				WhenMade  string 	 
				User      string  	
				Tag		  string    `json:"tag" binding:"required"`	   

				}
				var note NoteData
				c.BindJSON(&note)
				//get client key from cookie
				keyInCookie, err := c.Request.Cookie("key")
				keyVal,err := url.QueryUnescape(keyInCookie.Value)
				if err != nil{
					panic(err)
				}
				//Decode Client Key
				encryptedKey,err := hex.DecodeString(keyVal)
				if err != nil{
					panic(err)
				}
				//copy the first 24 bytes of ciphertext for the nonce
				var sessionNonce [24]byte
				copy(sessionNonce[:],encryptedKey[:24])

				dict,err := redis_session.Cmd("hgetall",id_cookie_val).Hash()
				if err != nil{
					panic(err)
				}
				//decode session key's hex string 
				sessionkey,err := hex.DecodeString(dict["key"])
				if err != nil{
					panic(err)
				}

				var sessionKey [32]byte
				copy(sessionKey[:],sessionkey)

				//decrypt client key with session key
				clientkey,ok := secretbox.Open(nil,encryptedKey[24:],&sessionNonce,&sessionKey) 
				if !ok {
					panic(err)
				} 
				//convert client key into [32]byte
				var clientKey [32]byte
				copy(clientKey[:],clientkey)

				//generate nonces
				var titleNonce [24]byte
				var noteNonce [24]byte
				if _, err := io.ReadFull(rand.Reader, titleNonce[:]); err != nil {
					panic(err)
				}
				if _, err := io.ReadFull(rand.Reader, noteNonce[:]); err != nil {
					panic(err)
				}
				t := time.Now()
				whenMade := t.Format("2006-01-02")

				//encrypt
				encryptedTitle:= secretbox.Seal(titleNonce[:],[]byte(note.Title),&titleNonce,&clientKey)
				encryptedNote := secretbox.Seal(noteNonce[:],[]byte(note.Note),&noteNonce,&clientKey)
				hexTitle := hex.EncodeToString(encryptedTitle)
				hexNote := hex.EncodeToString(encryptedNote)
				//store
				dbNote.Insert(NoteData{
					Title:hexTitle,
					Note:hexNote,
					WhenMade:whenMade,
					User:dict["user"],
					NoteType:note.NoteType,
					Tag:note.Tag,
					})
				
				c.JSON(200,gin.H{
				"response":"succ",
				})			

			}
			})

		//view single note
		route.GET("/view_note/:username/:noteid", func(c *gin.Context) {
		//get ID
			id_cookie, err := c.Request.Cookie("id")
			if err != nil{
				fmt.Println(err)
			}
			id_cookie_val,err := url.QueryUnescape(id_cookie.Value)
			if err != nil{
				panic(err)
			}

			//checksession
			asd := redis_session.Cmd("hmget",id_cookie_val,"user").String()
			if asd == "[ <nil> ]"{
				//session doesnt exist
				c.JSON(403,gin.H{
				"status":"unauthorized,fuck_off",
				})
			} else{	
			username := c.Param("username")
			noteid := c.Param("noteid")
			c.HTML(http.StatusOK,"view_single_note.tmpl",gin.H{
					"username":username,
					"noteid":noteid,
				})
			
		}
		})
		route.GET("/logout", func(c *gin.Context){
			c.JSON(200,gin.H{
				"get outta":"here",
				})
			})


		
	
	router.Run(":5000")
	
}
}

