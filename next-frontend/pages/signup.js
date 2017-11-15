
//to populate Head
import Head from 'next/head'
import axios from 'axios';
import NOSSR from 'react-no-ssr'
import SignUpForm from '../components/signupForm'
import React from 'react'
//function postData(){
//	axios.post()
//}

export default () =>(
	<div >
	<Head>
      <title>Signup  |  Aegis</title>
      <meta name="viewport" content="initial-scale=1.0, width=device-width" key="viewport" />
      <link rel="stylesheet" type="text/css" href="../static/css/uikit.min.css" />
    </Head>
    <br />
    <br />
	
	<div align="center">
	  <h1>Sign Up </h1>
	<br />
    <br />
	<NOSSR>
	< SignUpForm />
	</NOSSR>
	</div>
	 <script src="https://cdnjs.cloudflare.com/ajax/libs/uikit/3.0.0-beta.34/js/uikit.min.js"></script>
   <script src="/static/js/cryptostego.min.js"></script>

	</div>

	)