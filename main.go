package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/fzzy/radix/redis"        //redis
	"github.com/gin-gonic/gin"           //webserver
	"github.com/rs/xid"                  //UID generation
	"golang.org/x/crypto/bcrypt"         //password hashing
	"golang.org/x/crypto/nacl/secretbox" //golang nacl(Salsa20)
	"gopkg.in/mgo.v2"                    //mongo driver
	"gopkg.in/mgo.v2/bson"               //generate object ids
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"
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

func checkSession(c *gin.Context,client *redis.Client)(bool,string){
	idCookie, err := c.Request.Cookie("id")
	if err != nil{
		return false,"err"
	}
	idCookieVal, err := url.QueryUnescape(idCookie.Value)
	if err != nil{
		return false,"err"
	}
	check := client.Cmd("hmget",idCookieVal,"user").String()
	if check == "[ <nil> ]"{
		return false,"no session"
	}
	return true,idCookieVal
}

type LoginData struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	Key      string `json:"key" binding:"required"`
}

type User struct {
	id        bson.ObjectId
	Email     string
	Password  string
	AccType   string
	KeyHash   string
	StartDate string
	EndDate   string
}

type NoteData struct {
	id       bson.ObjectId
	Uuid     string
	Title    string
	Note     string
	NoteType string
	WhenMade string
	User     string
	Tags     string
}

type UserData struct {
	id        bson.ObjectId `bson:_id,omitempty`
	Email     string        `json:"email" binding:"required"`
	Password  string        `json:"password" binding:"required"`
	AccType   string        `json:"acc_type" binding:"required"`
	KeyHash   string        `json:"key_hash" binding:"required"`
	StartDate string
	EndDate   string
}

//func initRedis(){
//	redisSession, err := redis.DialTimeout("tcp","127.0.0.1:6379".time.Duration(10)*time.Second)
//}

func main() {
	mongoUrl, err := ioutil.ReadFile("private.txt")
	router := gin.Default()
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")
	session, err := mgo.Dial(string(mongoUrl))
	dbUser := session.DB("aegis").C("users")
	dbNote := session.DB("aegis").C("notes")
	redisSession, err := redis.DialTimeout("tcp", "127.0.0.1:6379", time.Duration(10)*time.Second)
	if err != nil {
		panic(err)

	}

	//ROutes
	route := router.Group("/")
	{

		//landing page
		route.GET("/", func(c *gin.Context) {
			c.HTML(http.StatusOK, "landing.tmpl", gin.H{})
		})

		//get key
		route.POST("/get_key", func(c *gin.Context) {
			key, err := GenerateRandomBytes(32)
			if err != nil {
				fmt.Println(err)
			}
			keyHash, err := bcrypt.GenerateFromPassword([]byte(string(key)), bcrypt.DefaultCost)
			if err != nil {
				fmt.Println(err)
			}

			encodedKey := hex.EncodeToString(key)

			c.JSON(200, gin.H{
				"key":      encodedKey,
				"key_hash": string(keyHash),
			})

		})

		//login
		route.GET("/login", func(c *gin.Context) {
			c.HTML(http.StatusOK, "login.tmpl", gin.H{})
		})

		route.POST("/login", func(c *gin.Context) {
			//get JSON data and bind
			var data LoginData
			c.BindJSON(&data)

			//Check if user exists
			user, err := dbUser.Find(bson.M{"email": data.Email}).Count()
			if err != nil {
				fmt.Println("user not found")
			}

			//if exists
			if user == 1 {
				result := User{}
				err := dbUser.Find(bson.M{"email": data.Email}).One(&result)
				if err != nil {
					fmt.Println("user not found")
				}
				//check if passwords match.
				hash := bcrypt.CompareHashAndPassword([]byte(result.Password), []byte(data.Password))
				if hash != nil {
					c.JSON(200, gin.H{
						"err": "wrong_user_pass",
					})
				} else {
					//if passwords match, see if their keys match.
					userKey, err := hex.DecodeString(data.Key)
					if err != nil {
						fmt.Println(err)
					}
					hash := bcrypt.CompareHashAndPassword([]byte(result.KeyHash), []byte(userKey))
					if hash != nil {
						c.JSON(200, gin.H{
							"err": "wrong_key",
						})
					} else {
						//Login successful
						//Generate UID
						uid := xid.New().String()

						//generate sessionKey
						key, err := GenerateRandomBytes(32)
						if err != nil {
							panic(err)
						}
						var sessionKey [32]byte
						copy(sessionKey[:], key)

						//generate nonce
						var nonce [24]byte
						if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
							fmt.Println("err making nonce")
						}

						//encrypt userKey with sessionKey
						userKey,err := hex.DecodeString(data.Key)
						if err != nil{
							panic(err)
						}
						encryptedKey := secretbox.Seal(nonce[:],userKey, &nonce, &sessionKey)

						//set session data
						postKey := hex.EncodeToString(key)
						sessionData := map[string]string{
							"sessionKey": postKey,
							"user":       result.Email,
						}

						//apply session
						apply := redisSession.Cmd("hmset", uid, sessionData)
						if apply == nil {
							panic("error creating session,redis insert failed")
						}
						encodedKey := hex.EncodeToString(encryptedKey)
						c.JSON(200, gin.H{
							"response": "succ",
							"key":      encodedKey,
							"id":       uid,
						})
					}

				}

			}

			//if not found
			if user == 0 {
				c.JSON(200, gin.H{
					"err": "wrong_user_pass",
				})
			}

		})

		//signup GET
		route.GET("/signup", func(c *gin.Context) {
			c.HTML(http.StatusOK, "signup.tmpl", gin.H{})
		})

		//signup POST
		route.POST("/signup", func(c *gin.Context) {
			//get the date today
			t := time.Now()
			StartDate := t.Format("2006-01-02")

			var data UserData
			c.BindJSON(&data)
			password, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)

			if err != nil {
				fmt.Println(err)
			}
			dbUser.Insert(UserData{
				Email:     data.Email,
				Password:  string(password),
				AccType:   data.AccType,
				KeyHash:   data.KeyHash,
				StartDate: StartDate,
				EndDate:   "ASD",
			})
		})

		//view all notes
		route.GET("/view_notes/:pagenum", func(c *gin.Context) {
			check,idCookieVal := checkSession(c,redisSession)
			if check != true{
				if idCookieVal != "err"{
					c.JSON(403, gin.H{
					"status": "unauthorized,fuck_off",
				})
					} else{
						panic("check session err")
					}	
			}else {

				//session exists

				//get user
				dict, err := redisSession.Cmd("hgetall", idCookieVal).Hash()
				if err != nil {
					panic(err)
				}
				var notes []NoteData

				//get page number before querying
				urlParam := c.Param("pagenum") + "0"
				skipNumber, err := strconv.Atoi(urlParam)
				if err != nil {
					panic(err)
				}
				//skip the first pagenumber * 10 results as they have been displayed in previous pages
				iter := dbNote.Find(bson.M{"user": dict["user"]}).Skip(skipNumber).Limit(10).Sort("-$natural").All(&notes)
				count, err := dbNote.Find(bson.M{"user": dict["user"]}).Count()
				fmt.Println(count)
				if err != nil {
					panic(err)
				}

				//all := iter.All(&notes)

				if iter != nil {
					fmt.Println("asd")
				}
				//get client key from cookie
				keyInCookie, err := c.Request.Cookie("key")
				keyVal, err := url.QueryUnescape(keyInCookie.Value)
				if err != nil {
					panic(err)
				}
				//Decode Client Key
				encryptedKey, err := hex.DecodeString(keyVal)
				if err != nil {
					panic(err)
				}
				//copy the first 24 bytes of ciphertext for the nonce
				var sessionNonce [24]byte
				copy(sessionNonce[:], encryptedKey[:24])

				//decode session key's hex string
				sessionkey, err := hex.DecodeString(dict["sessionKey"])
				if err != nil {
					panic(err)
				}

				var sessionKey [32]byte
				copy(sessionKey[:], sessionkey)

				//decrypt client key with session key
				clientkey, ok := secretbox.Open(nil, encryptedKey[24:], &sessionNonce, &sessionKey)
				if !ok {
					panic(err)
				}
				//convert client key into [32]byte
				var clientKey [32]byte
				copy(clientKey[:], clientkey)
				decryptedNotes := make([]NoteData, count)

				//for all notes
				for k, v := range notes {
					//decode the encrypted note
					decodedTitle, err := hex.DecodeString(v.Title)
					if err != nil {
						fmt.Println(err)
					}
					decodedNote, err := hex.DecodeString(v.Note)
					if err != nil {
						fmt.Println(err)
					}

					//get the nonce from the first 24 bytes
					var noteNonce [24]byte
					var titleNonce [24]byte
					copy(noteNonce[:], decodedNote[:24])
					copy(titleNonce[:], decodedTitle[:24])

					//decrypt the title
					boxTitle, ok := secretbox.Open(nil, decodedTitle[24:], &titleNonce, &clientKey)
					if !ok {
						fmt.Println(err)
					}
					boxNote, ok := secretbox.Open(nil, decodedNote[24:], &noteNonce, &clientKey)
					if !ok {
						fmt.Println(err)
					}

					//set decrypted values to insert into slice
					decryptedNote := NoteData{
						id:       v.id,
						Uuid:     v.Uuid,
						Title:    string(boxTitle),
						Note:     string(boxNote),
						NoteType: v.NoteType,
						WhenMade: v.WhenMade,
						User:     v.User,
						Tags:     v.Tags,
					}

					//append to splice
					decryptedNotes = append(decryptedNotes[:k], decryptedNote)
					if decryptedNotes == nil {
						panic("cant append")
					}

				}
				c.HTML(http.StatusOK, "view_notes.tmpl", gin.H{
					"notes":   decryptedNotes,
					"user":    dict["user"],
					"pagenum": c.Param("pagenum"),
				})

			}
		})

		//add note
		route.GET("/add_note/:notetype", func(c *gin.Context) {
			check,idCookieVal := checkSession(c,redisSession)
			if check != true{
				if idCookieVal != "err"{
					c.JSON(403, gin.H{
					"status": "unauthorized,fuck_off",
				})
					} else{
						panic("check session err")
					}	
			} else {
				dict, err := redisSession.Cmd("hgetall", idCookieVal).Hash()
				if err != nil {
					panic(err)
				}
				noteType := c.Param("notetype")
				if noteType == "text" {
					c.HTML(http.StatusOK, "add_note_text.tmpl", gin.H{
						"user":  dict["user"],
					})
				}
				if noteType == "audio" {
					c.JSON(403, gin.H{
						"status": "in_development",
					})
				}
			}
		})

		route.POST("/add_note", func(c *gin.Context) {
			//get ID
			check,idCookieVal := checkSession(c,redisSession)
			if check != true{
				if idCookieVal != "err"{
					c.JSON(403, gin.H{
					"status": "unauthorized,fuck_off",
				})
					} else{
						panic("check session err")
					}	
			} else {
				//session exists.
				type NoteData struct {
					id       bson.ObjectId `bson:_id,omitempty`
					Uuid     string
					Title    string `json:"title" binding:"required"`
					Note     string `json:"note" binding:"required"`
					NoteType string `json:"type" binding:"required"`
					WhenMade string
					User     string
					Tags     string `json:"tag" binding:"required"`
				}
				var note NoteData
				c.BindJSON(&note)
				//get client key from cookie
				keyInCookie, err := c.Request.Cookie("key")
				keyVal, err := url.QueryUnescape(keyInCookie.Value)
				if err != nil {
					panic(err)
				}
				//Decode Client Key
				encryptedKey, err := hex.DecodeString(keyVal)
				if err != nil {
					panic(err)
				}
				//copy the first 24 bytes of ciphertext for the nonce
				var sessionNonce [24]byte
				copy(sessionNonce[:], encryptedKey[:24])

				dict, err := redisSession.Cmd("hgetall", idCookieVal).Hash()
				if err != nil {
					panic(err)
				}
				//decode session key's hex string
				sessionkey, err := hex.DecodeString(dict["sessionKey"])
				if err != nil {
					panic(err)
				}

				var sessionKey [32]byte
				copy(sessionKey[:], sessionkey)

				//decrypt client key with session key
				clientkey, ok := secretbox.Open(nil, encryptedKey[24:], &sessionNonce, &sessionKey)
				if !ok {
					panic(err)
				}
				//convert client key into [32]byte
				var clientKey [32]byte
				copy(clientKey[:], clientkey)

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
				encryptedTitle := secretbox.Seal(titleNonce[:], []byte(note.Title), &titleNonce, &clientKey)
				encryptedNote := secretbox.Seal(noteNonce[:], []byte(note.Note), &noteNonce, &clientKey)
				hexTitle := hex.EncodeToString(encryptedTitle)
				hexNote := hex.EncodeToString(encryptedNote)
				//store
				dbNote.Insert(NoteData{
					Uuid:     xid.New().String(),
					Title:    hexTitle,
					Note:     hexNote,
					WhenMade: whenMade,
					User:     dict["user"],
					NoteType: note.NoteType,
					Tags:     note.Tags,
				})

				c.JSON(200, gin.H{
					"response": "succ",
				})

			}
		})

		//view single note
		route.GET("/view_note/:useremail/:noteuuid", func(c *gin.Context) {
			check,idCookieVal := checkSession(c,redisSession)
			if check != true{
				if idCookieVal != "err"{
					c.JSON(403, gin.H{
					"status": "unauthorized,fuck_off",
				})
					} else{
						panic("check session err")
					}	
			} else {

				//get URL params
				user := c.Param("useremail")
				noteuuid := c.Param("noteuuid")

				//query info and add result to dict
				result := NoteData{}
				err := dbNote.Find(bson.M{"user": user, "uuid": noteuuid}).One(&result)
				if err != nil {
					//if note wasn't found:
					c.JSON(403, gin.H{
						"status": "unauthorized,fuck_off",
					})
				}
				//get client key from cookie
				keyInCookie, err := c.Request.Cookie("key")
				keyVal, err := url.QueryUnescape(keyInCookie.Value)
				if err != nil {
					panic(err)
				}
				//Decode Client Key
				encryptedKey, err := hex.DecodeString(keyVal)
				if err != nil {
					panic(err)
				}
				//copy the first 24 bytes of ciphertext for the nonce
				var sessionNonce [24]byte
				copy(sessionNonce[:], encryptedKey[:24])

				dict, err := redisSession.Cmd("hgetall", idCookieVal).Hash()
				if err != nil {
					panic(err)
				}
				//decode session key's hex string
				sessionkey, err := hex.DecodeString(dict["sessionKey"])
				if err != nil {
					panic(err)
				}

				var sessionKey [32]byte
				copy(sessionKey[:], sessionkey)

				//decrypt client key with session key
				clientkey, ok := secretbox.Open(nil, encryptedKey[24:], &sessionNonce, &sessionKey)
				if !ok {
					panic(err)
				}
				//convert client key into [32]byte
				var clientKey [32]byte
				copy(clientKey[:], clientkey)

				//generate empty nonces
				var noteNonce [24]byte
				var titleNonce [24]byte

				//decode the note
				decodedNote, err := hex.DecodeString(result.Note)
				if err != nil {
					panic(err)
				}

				decodedTitle, err := hex.DecodeString(result.Title)
				if err != nil {
					panic(err)
				}

				//copy the nonces from first 24 bytes of ciphertext
				copy(noteNonce[:], decodedNote)
				copy(titleNonce[:], decodedTitle)

				//decrypt
				noteBox, ok := secretbox.Open(nil, decodedNote[24:], &noteNonce, &clientKey)
				if !ok {
					fmt.Println(err)
				}
				titleBox, ok := secretbox.Open(nil, decodedTitle[24:], &titleNonce, &clientKey)
				if !ok {
					fmt.Println(err)
				}
				result.Note = string(noteBox)
				result.Title = string(titleBox)

				c.JSON(200, gin.H{
					"note": result,
				})

			}
		})

		//Search by title.
		route.POST("/search_notes", func(c *gin.Context) {

			//define params
			type QueryParam struct {
				Type  string `json"type" binding="required"`
				User  string `json"user" binding="required"`
				Query string `json"query" binding="required"`
			}
			//bind data
			var query QueryParam
			c.BindJSON(&query)

			check,idCookieVal := checkSession(c,redisSession)
			if check != true{
				if idCookieVal != "err"{
					c.JSON(403, gin.H{
					"status": "unauthorized,fuck_off",
				})
					} else{
						panic("check session err")
					}	
			} else  {

				//session exists

				//get user
				dict, err := redisSession.Cmd("hgetall", idCookieVal).Hash()
				if err != nil {
					panic(err)
				}

				//search
				fmt.Println(query)
				fmt.Println("")
				fmt.Println("")
				fmt.Println("")
				fmt.Println(dict)

				if query.Type == "date" {
					fmt.Println("date")
				}
				if query.Type == "tag" {
					fmt.Println("tag")
				}
				c.JSON(200, gin.H{
					"type": query.Type,
				})

			}
		})
		route.GET("/logout", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"get outta": "here",
			})
		})

		route.GET("/pricing", func(c *gin.Context) {
			c.HTML(http.StatusOK, "pricing.tmpl", gin.H{
				"None": "None",
			})

		})

		router.RunTLS(":5000", "aegis.crt", "aegis.key")

	}
}
