package main

import(
	"fmt"
	"gopkg.in/mgo.v2"                    //mongo driver
	"gopkg.in/mgo.v2/bson"               //generate object ids
	"time"
	"io/ioutil"
)

type UserData struct {
	id        bson.ObjectId 
	Email     string        
	Password  string       
	AccType   string        
	KeyHash   string        
	StartDate string
	EndDate   string       
}

func checkAccountExpiration(dbUser *mgo.Collection){
	fmt.Println("CHECKING ACCS FOR EXPIRATION EVERY 24H")
	t := time.Now()
	date := t.Format("2006-01-02")
	var data []UserData
	iter:= dbUser.Find(bson.M{}).All(&data)
	if iter != nil{
		panic(iter)
	}
	for k,v := range data{
		//if date matches
		if v.EndDate == date{
			fmt.Println("expired!")
			fmt.Println(v.Email)
			fmt.Println(k)
		}
	}
}


func main() {
	mongoUrl, err := ioutil.ReadFile("private.txt")
	if err != nil {
		panic(err)

	}
	session, err := mgo.Dial(string(mongoUrl))
	dbUser := session.DB("aegis").C("users")
	checkAccountExpiration(dbUser)
}