import Link from 'next/link'
import React from 'react'
import axios from 'axios'



class SignUpForm extends React.Component{
  constructor(props){
    super(props)
    this.state = {email:'',password:'',passwordTwo:'',accType:'Free',months:'1',endDate:''}
    this.handleInputChange = this.handleInputChange.bind(this);
    this.handleSubmit = this.handleSubmit.bind(this);
  }
  

  handleInputChange(event){
    const target = event.target;
    const value =  target.value;
    const name = target.name;
    if (name == "months"){
      var endDate = new Date()
      endDate.setMonth(endDate.getMonth()+parseInt(value))
      
      //add one more day, as signup day is not counted.
      const dd = endDate.getDate()+1

      //add one to month as January is 0
      const mm = endDate.getMonth()+1
      const yyyy = endDate.getFullYear()
      console.log(mm)
      var endDate = yyyy+'-'+mm+"-"+dd
      this.setState({
        endDate:endDate
      })
    }
    this.setState({
      [name]:value
    })
    console.log(this.state)

  }


  handleSubmit(event){
    event.preventDefault();
    const email = this.state.email
    const password = this.state.password
    const accType = this.state.accType
    const endDate = this.state.endDate
    axios.post("https://0.0.0.0:5000/get_key",{
    }).then(function(response){
      const key = response.data.key
      const keyHash = response.data.key_hash
      
      function writeIMG(img_number){
        loadIMGtoCanvas(img_number,'canvas',function(){
        if(writeMsgToCanvas('canvas',key,password,0)!=null){ 
        var myCanvas = document.getElementById("canvas");  
        var image = myCanvas.toDataURL("image/png");    
        var element = document.createElement('a');
        element.setAttribute('href', image);
        element.setAttribute('download', 'key.png');
        element.style.display = 'none';
        document.body.appendChild(element);
        element.click();
        document.body.removeChild(element);   
        }},700)

      }
      writeIMG('image_one')
      writeIMG('image_two')
     
      axios.post("https://0.0.0.0:5000/signup",{
        email:email,
        password:password,
        acc_type:accType,
        end_date:endDate,
        key_hash:keyHash
      }).then(function(response){
        if (response.data.response == "succ"){
        UIkit.notification("<span uk-icon='icon: check'></span> Success!");
        }
      }).catch(function(err){
        console.log(err)
      })
    
    }).catch(function(err){
      console.log(err)
    })

  }
  render(){
    return(
    <form onSubmit={this.handleSubmit}>
       <label>Email</label>
          <input name="email" type="text" className="uk-input uk-form-width-large" value={this.state.email} onChange={this.handleInputChange} />
          
          <br />
          <br />

          <label>Password</label>
          <input name="password"  className="uk-input uk-form-width-large" type="password" value={this.state.password} onChange={this.handleInputChange} />

          <br />
          <br />
         
         <label>Password Again</label>
          <input name="passwordTwo"  className="uk-input uk-form-width-large" type="password" value={this.state.passwordTwo} onChange={this.handleInputChange} />

          <br />
          <br />

          <input type="file" id="image_one"></input>
          <input type="file"  id="image_two"></input>
          <br />
          <br />


        <select className="uk-select uk-form-width-small" value={this.state.accType} name="accType" onChange={this.handleInputChange}>
          <option value="free">Free</option>
          <option value="premium">Premium</option>
        </select>


        < br />
        < br />
        

        <select className="uk-select uk-form-width-small" value={this.state.months} name="months" onChange={this.handleInputChange}>
          <option value="1">1</option>
          <option value="2">2</option>
          <option value="3">3</option>
          <option value="4">4</option>
          <option value="5">5</option>
          <option value="6">6</option>
          <option value="7">7</option>
          <option value="8">8</option>
          <option value="9">9</option>
          <option value="10">10</option>
          <option value="11">11</option>
          <option value="12">12</option>
        </select>

          <br />
          <br />
          <button type="submit" className="uk-button uk-button-primary">Submit</button>

    </form>
    )
  }
}


const signUpForm = () =>(
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