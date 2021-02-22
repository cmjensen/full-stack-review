CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    email VARCHAR(45) NOT NULL,
    username VARCHAR(25) NOT NULL,
    password VARCHAR(500) NOT NULL
)

CREATE TABLE posts (
    post_id SERIAL PRIMARY KEY,
    img_url TEXT,
    title VARCHAR(50),
    karma INT DEFAULT 0,
    user_id INT REFERENCES users(user_id)
)