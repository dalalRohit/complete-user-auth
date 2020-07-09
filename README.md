# Complete User Authentication 
A complete and easy to integrate User-Authentication REST API for any application with Express.js and MongoDB as backend.

# How to use
	1. Clone or download the repository
	2. Open project in your favorite IDE
	3. Run npm install in cloned directory
	4. Start the app by running npm run dev and open [Postman] (https://www.postman.com/)

# Features
	1. JWT authentication
	2. Simple Mongoose model with one instance method for JWT token generation
	3. Easy to integrate with any Front-end application
	4. Authentication middleware is added for protected routes

# Routes
1. POST Routes
	1. /register <br/>
		Accepts ```{username,email,password,password_confirm}``` and returns user ID on successful registration. 
	
  	2. /login <br/>
		Accepts ```{username,password}``` and returns JWT "Auth-Token" for subsequent requests to protected routes
		
  	3. /user/:id <br/>
		Returns a user with given ```{id}``` as a URL parameter
	
2. GET routes
  	1. /users
  	2. /test
  	3. /logout
  	4. /logoutall
  	5. /check
	
3. PUT routes
  	1. /update/:id
