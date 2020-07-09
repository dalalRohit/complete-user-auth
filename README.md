# Complete User Authentication 
A complete and easy to integrate User-Authentication REST API for any application with Express.js, MongoDB as backend and DB respectively

# How to use
	1. Clone or download the repository
	2. Open project in your favourite IDE ( I assume VS Code ;) )
	3. Run npm install in cloned directory
	4. Start MongoDB service in your machine
	5. Change the connection string of DB in db/db.js
	5. Start the app by running npm run dev and open POSTMAN.
	6. Start with POST /register and rest is all yours ;)

# Features
	1. JWT authentication
	2. Simple Mongoose model with one instance method for JWT token generation.
	3. Form/JSON data validation using @hapi/joi. 
	4. Authentication middleware is added for protected routes.
	5. Easy to integrate with any Front-end application.
	6. Neat and Well documented code for easy understanding.



# Routes
1. POST Routes
	1. /register <br/>
		Accepts ```{username,email,password,password_confirm}``` and returns user ID on successful registration. 
	
  	2. /login <br/>
		Accepts ```{username,password}``` and returns JWT "Auth-Token" which can be used for subsequent requests to protected routes
		
  	3. /user/:id <br/>
		Returns a user with given ```{id}``` as a URL parameter
	
2. GET routes
  	1. /users <br/>
	  	List all stored users from DB

  	2. /test <br/>
		Sample protected route

  	3. /logout <br/>
	  	Logs user out from current session

  	4. /logoutall <br/>
	  	Logs user out from all logged in sessions

  	5. /check <br/>
		Check if given JWT token is valid or not

3. PUT routes
  	1. /update/:id <br/>
	  Update password (or any other details you want) of the user with given id
