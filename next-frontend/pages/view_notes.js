import Head from 'next/head'
import cookie from "js-cookie"
import axios from 'axios'
import https from 'https'
import React, { Component } from 'react'
//import GetNotes from '../components/renderViewNotes'
import NOSSR from 'react-no-ssr'


export default class GetNotes extends React.Component {
 	static async getInitialProps ({query, req}) {
 	if (process.browser){
 		console.log("browser")
 	}
 	const instance = axios.create({
 		httpsAgent : new https.Agent({
 			rejectUnauthorized:false
 		})
 	});
	const querytype = "all"
	const url = "https://0.0.0.0:5000/view_notes"
	const response = await instance.post(url,{
    pagenum:query.pagenum,
    querytype:querytype,
    query:"none",
    user:"asd",
    key:req.cookies.key,
    id:req.cookies.id
  	})

	const notes = response.data.notes

  	return {
  		notes:notes
  	}

		} 
  	
   

   constructor(props){
    super(props);
    this.state = {notes:this.props.notes};
    this.post = this.post.bind(this);
  }
  post(event){
	console.log("event")
	}

  render () {
  	var  data  = this.props.notes[0]
  	const content = this.props.notes.map((note) =>
  		
  		<div key={note.Uuid}>
        	<h1>{note.Uuid}</h1>
        	<h1>{note.Title}</h1>
        	<br/>
  		</div>
  
  	);

  	return(
  	<div>
  	{content}
     
    </div>
    )
  }
    
}
	

