package main

import "github.com/gin-gonic/gin"
//import "net/http"
import "fmt"
import "gopkg.in/mgo.v2"
//import "gopkg.in/mgo.v2/bson"

func main() {
	router := gin.Default()
	session, err := mgo.Dial("uri")
	c := session.DB('aegis').C('users')

	//login group
	route := router.Group("/")
	{
		//login
		route.GET("/login",func(c *gin.Context){
			c.JSON(200,gin.H{
				"message":"pong",
				})
			})
		route.POST("/login",func(c *gin.Context){
			//get JSON data
			var data struct {
				username string `json:"username" binding:"required"`
				password string `json:"password" binding:"required"`
				imageHash string `json:"img_hash" binding:"required"`
			}
			//Check if user exists

			c.JSON(200,gin.H{
				"message":"pong",
				})
			})

		//signup
		route.GET("/signup",func(c *gin.Context){
			c.JSON(200,gin.H{
				"message":"pong",
				})
			})
		route.POST("/signup",func(c *gin.Context){
			c.JSON(200,gin.H{
				"message":"pong",
				})
			})


		//view all notes
		route.POST("/view_all_notes/",func(c *gin.Context) {
			//collect JSON Data and store in dict

			var json struct {
				Username string `json:"username" binding:"required"`

			}

			//Bind
			c.Bind(&json)

			//return resposne
			c.JSON(200,json)
			fmt.Println("works")
			


			
		})

	}
	
	router.Run(":5000")
	
}

