import NOSSR from 'react-no-ssr'
//to populate Head
import Head from 'next/head'
//login form
import LoginForm from '../components/loginForm'

export default () =>(
	 <div>
	<Head>
      <title>Login  |  Aegis</title>
      <meta name="viewport" content="initial-scale=1.0, width=device-width" key="viewport" />
      <link rel="stylesheet" type="text/css" href="../static/css/uikit.min.css" />
    </Head>
	   <div align="center">
     <h1>Login </h1>
     <NOSSR >
      < LoginForm/>
     </NOSSR>
    </div>
   <script src="https://cdnjs.cloudflare.com/ajax/libs/uikit/3.0.0-beta.34/js/uikit.min.js"></script>
   <script src="/static/js/cryptostego.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/js-cookie/2.1.4/js.cookie.min.js"></script>

   
  </div>

	)