package main

import(
	"fmt"
	"strconv"
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
 	"golang.org/x/crypto/nacl/secretbox" //golang nacl(Salsa20) 
	"encoding/hex" 
	"github.com/fzzy/radix/redis"//redis

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
	Uuid	  string
	Title	  string 	 	
	Note      string 	
	NoteType  string 	
	WhenMade  string 	
	User      string  	
	Tags  	  string  	   
}


func main() {
	b, err := ioutil.ReadFile("private.txt")
	router := gin.Default()
	websocket := melody.New()
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
				fmt.Println("single user not found")
			}

			//if exists
			if user == 1{
				result := User{}
				err := dbUser.Find(bson.M{"email":data.Email}).One(&result)
				if err != nil{
					fmt.Println("user not found")
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
						fmt.Println("keys dont match")
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
							fmt.Println("cant generate key")
						}
						//Generate random nonce
						var nonce [24]byte
						if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
    						fmt.Println("cant generate random nonce")
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
		route.GET("/view_notes/:pagenum",func(c *gin.Context) {
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

				//get page number before querying
				urlParam := c.Param("pagenum")+"0"
				skipNumber,err := strconv.Atoi(urlParam)
				if err != nil{
					panic(err)
				} 
				//skip the first pagenumber * 10 results as they have been displayed in previous pages 
				iter := dbNote.Find(bson.M{"user": dict["user"]}).Skip(skipNumber).Limit(10).Sort("-$natural").All(&notes)
				count,err := dbNote.Find(bson.M{"user": dict["user"]}).Count()
				fmt.Println(count)
				if err != nil{
					panic(err)
				}

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
				decryptedNotes := make([]NoteData,count) 

				//for all notes
				for k,v := range notes{
					//decode the encrypted note
					decodedTitle,err := hex.DecodeString(v.Title)
					if err != nil{
						fmt.Println(err)
					}
					decodedNote,err  := hex.DecodeString(v.Note)
					if err != nil{
						fmt.Println(err)
					}
					

					//get the nonce from the first 24 bytes
					var noteNonce [24]byte
					var titleNonce [24]byte
					copy(noteNonce[:],decodedNote[:24])
					copy(titleNonce[:],decodedTitle[:24])
					
					//decrypt the title
					boxTitle,ok := secretbox.Open(nil,decodedTitle[24:],&titleNonce,&clientKey)
					if !ok{
						fmt.Println(err)
					} 
					boxNote,ok := secretbox.Open(nil,decodedNote[24:],&noteNonce,&clientKey)
					if !ok{
						fmt.Println(err)
					}
					
					//set decrypted values to insert into slice
					decryptedNote := NoteData{
						id:v.id,
						Uuid:v.Uuid,
						Title:string(boxTitle),
						Note:string(boxNote),
						NoteType:v.NoteType,
						WhenMade:v.WhenMade,
						User:v.User,
						Tags:v.Tags,
					}

					//append to splice
					decryptedNotes = append(decryptedNotes[:k],decryptedNote)
					if decryptedNotes == nil{
						panic("cant append")
					}



					
				}
				c.HTML(http.StatusOK,"view_notes.tmpl",gin.H{
					"notes":decryptedNotes,
					"user":dict["user"],
					"pagenum":c.Param("pagenum"),

				})

				
			}
			})

		//add note
		route.GET("/add_note/:notetype", func(c *gin.Context) {
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
			dict,err := redis_session.Cmd("hgetall",id_cookie_val).Hash()
			if err != nil{
				panic(err)
			}
			noteType := c.Param("notetype")
			if noteType == "text"{			
			c.HTML(http.StatusOK, "add_note_text.tmpl", gin.H{
				"login":"login",
				"user": dict["user"],
				})
			}
			if noteType == "audio"{
				c.JSON(403,gin.H{
				"status":"in_development",
				})
			}
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
				Uuid	  string 	
				Title	  string 	`json:"title" binding:"required"`
				Note      string 	`json:"note" binding:"required"`
				NoteType  string 	`json:"type" binding:"required"` 
				WhenMade  string 	 
				User      string  	
				Tags	  string    `json:"tag" binding:"required"`	   

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
					fmt.Println("err making titlenonce")
				}
				if _, err := io.ReadFull(rand.Reader, noteNonce[:]); err != nil {
					fmt.Println("err making notenonce")
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
					Uuid:xid.New().String(),
					Title:hexTitle,
					Note:hexNote,
					WhenMade:whenMade,
					User:dict["user"],
					NoteType:note.NoteType,
					Tags:note.Tags,
					})
				
				c.JSON(200,gin.H{
				"response":"succ",
				})			

			}
			})

		//view single note
		route.GET("/view_note/:useremail/:noteuuid", func(c *gin.Context) {
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

			//get URL params	
			user := c.Param("useremail")
			noteuuid := c.Param("noteuuid")
			
			//query info and add result to dict
			result := NoteData{}
			err := dbNote.Find(bson.M{"user":user,"uuid":noteuuid}).One(&result)
			if err != nil{
				//if note wasn't found:
				c.JSON(403,gin.H{
				"status":"unauthorized,fuck_off",
				})
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

			//generate empty nonces
			var noteNonce [24]byte
			var titleNonce [24]byte
			
			//decode the note
			decodedNote,err := hex.DecodeString(result.Note)
			if err != nil{
				panic(err)
			}

			decodedTitle,err := hex.DecodeString(result.Title)
			if err != nil{
				panic(err)
			}

			//copy the nonces from first 24 bytes of ciphertext
			copy(noteNonce[:],decodedNote)
			copy(titleNonce[:],decodedTitle)

			//decrypt 
			noteBox,ok := secretbox.Open(nil,decodedNote[24:],&noteNonce,&clientKey)
			if !ok{
				fmt.Println(err)
			} 
			titleBox,ok := secretbox.Open(nil,decodedTitle[24:],&titleNonce,&clientKey)
			if !ok{
				fmt.Println(err)
			}	
			result.Note = string(noteBox)
			result.Title = string(titleBox)

			c.JSON(200,gin.H{
					"note":result,
				})
			
		}
		})
		route.GET("/logout", func(c *gin.Context){
			c.JSON(200,gin.H{
				"get outta":"here",
				})
			})

		route.GET("/pricing",func(c *gin.Context) {
			c.HTML(http.StatusOK, "pricing.tmpl", gin.H{
				"None":"None",
				})
			
		})
	
	router.RunTLS(":5000","aegis.crt","aegis.key")
	
}
}
