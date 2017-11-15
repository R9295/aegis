import Link from 'next/link'
import React from 'react'
import axios from 'axios'
/*

    */


class LoginForm extends React.Component{
  constructor(props){
    super(props);
    this.state = {email: '',password: '',key:'',status:''};
    this.handleInputChange = this.handleInputChange.bind(this);
    this.handleSubmit = this.handleSubmit.bind(this);
  }
  handleInputChange(event){
    const target = event.target;
    const value =  target.value;
    const name = target.name;
    console.log("name: "+name)
    console.log("value: "+value)

    this.setState({
      [name]:value
    })
    console.log(this.state)
    
  }
  handleSubmit(event){
    event.preventDefault();
    const email = this.state.email
    const password = this.state.password
    loadIMGtoCanvas('file','canvas',function(){
      var t = readMsgFromCanvas('canvas',password,0);
       if (t!=null){
         t=t.split('&').join('&amp;');
        t=t.split('<').join('&lt;');
         t=t.split('>').join('&gt;');
         console.log(t)      
     } 
     axios.post("https://0.0.0.0:5000/login",{
      email:email,
      password:password,
      key:t
     }).then(function(response){
      if (response.data.response == "succ"){
        UIkit.notification("<span uk-icon='icon: check'></span> Success");
            Cookies.set('id',response.data.id)
            Cookies.set('key',response.data.key)
            window.location="/view_notes/0"
      }
     }).catch(function(err){
      console.log(err)
     })

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
          <input name="password"  className="uk-input uk-form-width-large" type="text" value={this.state.password} onChange={this.handleInputChange} />

          <br />
          <br />
          
          <label>Key</label>
          <input type="file" id="file" />
          <h1>{this.state.status}</h1>
          <input type="submit" value="Submit" className="uk-button uk-button-primary" />

        </form>
      )
  }
}





export default LoginForm