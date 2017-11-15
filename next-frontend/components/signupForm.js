import Link from 'next/link'


const SignUpForm = () =>(
	<div align="center" className="uk-container uk-container-small">
		<h1>SignUp</h1>
    	
    	<label>Email address</label>
   		<input type="email" className="uk-input uk-form-width-large" id="email" aria-describedby="emailHelp" />
   		<br />
   		<br />

   		<label>Password</label>
    	<input type="password" className="uk-input uk-form-width-large" id="password"></input>
    	<br/>
    	<br/>

      <label>Password Again</label>
      <input type="password" className="uk-input uk-form-width-large" id="password_two" placeholder="Password"></input>
      <br />
      <br />


  	
      <input type="file" className="uk-input uk-form-width-large" id="image_one"></input>
      <button className="uk-button uk-button-default">Image One</button>
 
    	<input type="file" className="uk-input uk-form-width-large" id="image_two"></input>
    	<button className="uk-button uk-button-default">Image Two</button>
 
  	<br />
  	<br />
  	<select className="uk-select uk-form-width-small" id="acc_type" name="account_type">
      <option value="free">Free</option>
      <option value="premium">Premium</option>
    </select>
    < br />
    < br />
     <select className="uk-select uk-form-width-small" id="months" name="account_type">
   <option>1</option>
   <option>2</option>
   <option>3</option>
   <option>4</option>
   <option>5</option>
   <option>6</option>
   <option>7</option>
   <option>8</option>
   <option>9</option>
   <option>10</option>
   <option>11</option>
   <option>12</option>
 </select>
 <br />
 <br />
  	<h1 id="status"></h1>
  	<button type="submit" className="uk-button uk-button-primary">Submit</button>

       <script src="https://cdnjs.cloudflare.com/ajax/libs/uikit/3.0.0-beta.34/js/uikit.min.js"></script>

    </div>
	)
export default SignUpForm