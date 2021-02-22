# Reddit Clone Planning

</hr>

MVP (minimum features)
- users can create an account
- users can login
- users can create a post 
- users can update a post
- users can read all posts

ICEBOX (additional features)
- posts will be organized from most to least upvotes
- users can up/down vote posts
- users can add/update/delete comments
- users can up/down vote comments

# DATABASE

users

```SQL
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(45) NOT NULL,
    username VARCHAR(25) NOT NULL,
    password VARCHAR(500) NOT NULL
)
```

posts
```SQL
CREATE TABLE posts (
    post_id SERIAL PRIMARY KEY,
    img_url TEXT,
    title VARCHAR(50),
    karma INT DEFAULT 0,
    user_id INT REFERENCES users(user_id)
)
```

# SERVER

- Dependencies: 
    - massive (for connecting to our postgreSQL db)
    - express (for writing RESTful functionality)
    - express-session (for initializing a session for each user)
    - bcrypt (for hashing passwords for authentication)
    - dotenv    (to access environmental variables that are in our .gitignore)

- File Structure:
    - server/
        - index.js
        - controllers/
            - authController.js
            - postController.js

- Endpoints:
    AUTH ENDPOINTS
    - register => `/auth/register`
    - login => `/auth/login`
    - logout => `/auth/logout`
    - getUserSession => `/auth/get_user` (allows the login to persist even when a page is refreshed)

    POST ENDPOINTS
    - getPosts => `/api/posts`
    - deletePost => `/api/posts/:id`
    - editPost => `/api/posts/:id`
    - addPost => `/api/post`

# FRONTEND
- Dependencies:
    - axios (requests to server)
    - redux
    - react-redux
    - redux-promise-middleware (for asynchronous functionality)
    - react-router-dom

-- First, build a wireframe

- File Structure:
    -src/
        - App.js
        - reset.css
        - routes.js
        - redux/
            - store.js
            - .js
        - components/
            - Header.js
            - Auth.js
            - Form.js
            - Main.js

