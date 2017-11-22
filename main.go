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
	"strconv"
	"time"
	"github.com/gin-contrib/cors"

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

func checkSession(id string, client *redis.Client) (bool, string) {
	check := client.Cmd("hmget",id, "user").String()
	if check == "[ <nil> ]" {
		return false, "no session"
	}
	return true, id
}

func getNotes(dbNote *mgo.Collection, queryType string, user string, userKey []byte, query string,pagenum string) []NoteData {
	var notes []NoteData
	var count int
	//if get all notes
	if queryType == "all" {
		skipNumber, err := strconv.Atoi(pagenum)
		if err != nil {
			panic(err)
		}

		fmt.Println("skipnumber:", skipNumber)
		iter := dbNote.Find(bson.M{"user": user}).Skip(skipNumber).Limit(10).Sort("-$natural").All(&notes)
		if iter != nil {
			fmt.Println("no notes found all")
		}
		count, err := dbNote.Find(bson.M{"user": user}).Count()
		if err != nil {
			panic(err)
		}

		if count == 0 {
			fmt.Println("no notes found")
		}

	}
	//if get notes by queryType date
	if queryType == "date" {
		skipNumber, err := strconv.Atoi(pagenum)
		if err != nil {
			panic(err)
		}
		count, err := dbNote.Find(bson.M{"user": user, "whenmade": query}).Count()
		if err != nil {
			panic(err)
		}
		iter := dbNote.Find(bson.M{"user": user, "whenmade": query}).Skip(skipNumber).Limit(10).All(&notes)
		if iter != nil {
			panic("no notes found date")
		}
		
		if count == 0 {
			panic("no notes found")
		}

	}

	//if get notes by queryType tags
	if queryType == "tags" {
		skipNumber, err := strconv.Atoi(pagenum)
		if err != nil {
			panic(err)
		}
		fmt.Println("TAGS")
		iter := dbNote.Find(bson.M{"user": user, "tags": query}).Skip(skipNumber).Limit(10).Sort("-$natural").All(&notes)
		if iter != nil {
			panic("no notes found tag")
		}
		count, err := dbNote.Find(bson.M{"user": user, "tags": query}).Count()
		if err != nil {
			panic(err)
		}
		if count == 0 {
			panic("no notes found")
		}

	}

	//create key
	var key [32]byte
	copy(key[:], userKey)
	decryptedNotes := make([]NoteData, count)

	//decrypt each note found and append it decrypted to list to return.
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
		boxTitle, ok := secretbox.Open(nil, decodedTitle[24:], &titleNonce, &key)
		if !ok {
			fmt.Println(err)
		}

		boxNote, ok := secretbox.Open(nil, decodedNote[24:], &noteNonce, &key)
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
	return decryptedNotes

}

func getClientKey(sessionKey string, userKey string) []byte {
	encryptedKey, err := hex.DecodeString(userKey)
	if err != nil {
		panic(err)
	}
	fmt.Println(encryptedKey)
	var nonce [24]byte
	copy(nonce[:], encryptedKey[:24])

	key, err := hex.DecodeString(sessionKey)
	if err != nil {
		panic(err)
	}

	var sessionkey [32]byte
	copy(sessionkey[:], key)
	clientKey, ok := secretbox.Open(nil, encryptedKey[24:], &nonce, &sessionkey)
	if !ok {
		panic(err)
	}
	return clientKey

}
func getSingleNote(dbNote *mgo.Collection, userKey []byte, uuid string, user string) (bool, NoteData) {

	//append data to struct
	result := NoteData{}
	findNote := dbNote.Find(bson.M{"user": user, "uuid": uuid}).One(&result)
	if findNote != nil {
		//if response not empty, means the user doesn't own the note.
		return false, result
	}


	//convert key
	var key [32]byte
	copy(key[:], userKey)

	//generate empty nonces
	var noteNonce [24]byte
	var titleNonce [24]byte

	//decode note and title to decrypt
	decodedNote, err := hex.DecodeString(result.Note)
	if err != nil {
		panic(err)
	}

	decodedTitle, err := hex.DecodeString(result.Title)
	if err != nil {
		panic(err)
	}

	//copy nonces from box
	copy(noteNonce[:], decodedNote[:24])
	copy(titleNonce[:], decodedTitle[:24])

	//decrypt
	noteBox, ok := secretbox.Open(nil, decodedNote[24:], &noteNonce, &key)
	if !ok {
		panic(err)
	}

	titleBox, ok := secretbox.Open(nil, decodedTitle[24:], &titleNonce, &key)
	if !ok {
		panic(err)
	}
	result.Note = string(noteBox)
	result.Title = string(titleBox)
	return true, result

}

func addNote(dbNote *mgo.Collection, userKey []byte, noteType string, user string, tags string, note string, title string) bool {
	var key [32]byte
	copy(key[:], userKey)

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
	encryptedTitle := secretbox.Seal(titleNonce[:], []byte(title), &titleNonce, &key)
	encryptedNote := secretbox.Seal(noteNonce[:], []byte(note), &noteNonce, &key)
	hexTitle := hex.EncodeToString(encryptedTitle)
	hexNote := hex.EncodeToString(encryptedNote)
	//store
	dbNote.Insert(NoteData{
		Uuid:     xid.New().String(),
		Title:    hexTitle,
		Note:     hexNote,
		WhenMade: whenMade,
		User:     user,
		NoteType: noteType,
		Tags:     tags,
	})
	return true

}

type PostNoteData struct {
	id       bson.ObjectId `bson:_id,omitempty`
	Uuid     string
	Title    string `json:"title" binding:"required"`
	Note     string `json:"note" binding:"required"`
	NoteType string `json:"type" binding:"required"`
	WhenMade string
	User     string
	Tags     string `json:"tag" binding:"required"`
}

type QueryParam struct {
	QueryType string `json"querytype" binding="required"`
	User      string `json"user" binding="required"`
	Query     string `json"query" binding="required"`
}

type LoginData struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
	Key      string `json:"key" binding:"required"`
}

type User struct {
	id        bson.ObjectId
	Uuid      string
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
	Uuid 	  string
	Email     string        `json:"email" binding:"required"`
	Password  string        `json:"password" binding:"required"`
	AccType   string        `json:"acc_type" binding:"required"`
	KeyHash   string        `json:"key_hash" binding:"required"`
	StartDate string
	EndDate   string        `json:"end_date" binding:"required"`
}

func main(){
	mongoUrl, err := ioutil.ReadFile("private.txt")
	if err != nil {
		panic(err)

	}

	router := gin.Default()
	router.Use(cors.Default())
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")
	session, err := mgo.Dial(string(mongoUrl))
	dbUser := session.DB("aegis").C("users")
	dbNote := session.DB("aegis").C("notes")
	redisSession, err := redis.DialTimeout("tcp", "127.0.0.1:6379", time.Duration(10)*time.Second)
	if err != nil {
		panic(err)

	}

	//routers
	
		//get key
		router.POST("/get_key", func(c *gin.Context) {
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
		router.POST("/login", func(c *gin.Context) {
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
						userKey, err := hex.DecodeString(data.Key)
						if err != nil {
							panic(err)
						}
						encryptedKey := secretbox.Seal(nonce[:], userKey, &nonce, &sessionKey)

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
						fmt.Println(encodedKey)
						c.JSON(200, gin.H{
							"response": "succ",
							"key":      data.Key,
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

		//signup POST
		router.POST("/signup", func(c *gin.Context) {
			//get the date today
			t := time.Now()
			StartDate := t.Format("2006-01-02")

			var data UserData
			c.BindJSON(&data)
			fmt.Println(data)
			password, err := bcrypt.GenerateFromPassword([]byte(data.Password), bcrypt.DefaultCost)

			if err != nil {
				fmt.Println(err)
			}
			dbUser.Insert(UserData{
				Uuid:      xid.New().String(),
				Email:     data.Email,
				Password:  string(password),
				AccType:   data.AccType,
				KeyHash:   data.KeyHash,
				StartDate: StartDate,
				EndDate:   data.EndDate,
			})
			c.JSON(200, gin.H{
				"response": "succ",			
			})
		})

		router.POST("/view_notes", func(c *gin.Context) {
				type Asd struct{
					PageNum    string  `json:"pagenum" binding:"required"`
					QueryType    string  `json:"querytype" binding:"required"`
					Query    string  `json:"query" binding:"required"`
					User    string  `json:"user" binding:"required"`
					Key    string  `json:"key" binding:"required"`
					Id    string  `json:"id" binding:"required"`

				}
				var data Asd
				c.BindJSON(&data)
				urlParam := data.PageNum + "0"
				key,err := hex.DecodeString(data.Key)
				if err != nil{
					panic(err)
				}
				if data.QueryType == "date" {
					//format data sent
					year := data.Query[0:4]
					month := data.Query[4:6]
					day := data.Query[6:8]
					query := year+"-"+month+"-"+day
					results := getNotes(dbNote,"date",data.User,key,query,urlParam)
					c.JSON(200,gin.H{
					"notes":   results,
					"pagenum": data.PageNum,
				})
				}
				if data.QueryType == "tags" {
					results := getNotes(dbNote,"tags",data.User,key,data.Query,urlParam)
					c.JSON(200,gin.H{
					"notes":   results,
					"pagenum": data.PageNum,
					})

				}
				if data.QueryType == "all"{
					results := getNotes(dbNote,"all",data.User,key," ",urlParam)
					c.JSON(200,gin.H{
					"notes":   results,
					"pagenum": data.PageNum,
					})
					
				}
				
				
		})





		router.RunTLS(":5000", "aegis.crt", "aegis.key")

	

}