
//to populate Head
import Head from 'next/head'
import axios from 'axios';
import SignUpForm from '../components/signupForm'
import React from 'react'
//function postData(){
//	axios.post()
//}

export default () =>(
	<div>
	<Head>
      <title>Login  |  Aegis</title>
      <meta name="viewport" content="initial-scale=1.0, width=device-width" key="viewport" />
      <link rel="stylesheet" type="text/css" href="../static/css/uikit.min.css" />
    </Head>
	
	<SignUpForm />
	</div>

	)