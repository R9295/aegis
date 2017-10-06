package main

import "github.com/gin-gonic/gin"
import "net/http"

func main() {
	router := gin.Default()
	router.GET("/user/:name",func(c *gin.Context) {
		name := c.Param("name")
		c.String(http.StatusOK,"Hello %s",name)
		
	})
	router.Run()
	
}