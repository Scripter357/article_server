# Спецификации сервера
Веб сервер: Uvicorn
Фреймворк: FastAPI
Зависимости: requests, os, psycopg2, datetime, flask, jose, passlib, pydantic, json
БД: postgresql на localhost:5432
Имя БД: server_db

# Структура базы данных
CREATE TABLE article_comment(
  comment_id INT NOT NULL,
  article_id INT NOT NULL,
  PRIMARY KEY (comment_id, article_id),
  FOREIGN KEY (comment_id)
    REFERENCES comments (comment_id),
  FOREIGN KEY (article_id)
    REFERENCES articles (article_id)
)
CREATE TABLE article_ratings(
  rating_id INT NOT NULL,
  article_id INT NOT NULL,
  PRIMARY KEY (rating_id, article_id),
  FOREIGN KEY (rating_id)
    REFERENCES ratings (rating_id),
  FOREIGN KEY (article_id)
    REFERENCES articles (article_id)
)
CREATE TABLE comments (
  comment_id serial PRIMARY KEY,
  c_text TEXT
)
CREATE TABLE ratings (
  rating_id serial PRIMARY KEY,
  stars SMALLINT,
  r_text TEXT
)
CREATE TABLE article_writers (
  uid INT NOT NULL,
  article_id INT NOT NULL,
  PRIMARY KEY (article_id, uid),
  FOREIGN KEY (uid)
    REFERENCES users (uid),
  FOREIGN KEY (article_id)
    REFERENCES articles (article_id)
)
CREATE TABLE topic_articles(
  topic_id INT NOT NULL,
  article_id INT NOT NULL,
  PRIMARY KEY (topic_id, article_id),
  FOREIGN KEY (topic_id)
    REFERENCES topics (topic_id),
  FOREIGN KEY (article_id)
    REFERENCES articles (article_id)
)
CREATE TABLE articles (
  article_id serial PRIMARY KEY,
  title VARCHAR (100),
  text TEXT,
  status VARCHAR (10),
  publish_time TIMESTAMP
)
CREATE TABLE topics(
  topic_id serial PRIMARY KEY,
  name VARCHAR (50) NOT NULL
)
CREATE TABLE user_roles (
  uid INT NOT NULL,
  role_id INT NOT NULL,
  PRIMARY KEY (uid, role_id),
  FOREIGN KEY (role_id)
      REFERENCES roles (role_id),
  FOREIGN KEY (uid)
      REFERENCES users (uid)
)
CREATE TABLE roles (
  role_id serial PRIMARY KEY,
  role_name VARCHAR ( 50 ) UNIQUE NOT NULL
)
CREATE TABLE users (
  uid serial PRIMARY KEY,
  username VARCHAR ( 50 ) UNIQUE NOT NULL,
  password VARCHAR ( 50 ) NOT NULL,
  ban BOOLEAN NOT NULL
)

# API
POST
/token
Login For Access Token

POST
/user/sign_up
Sign Up

POST
/user/assign_role
Assign Role

POST
/user/unassign_role
Unassign Role

POST
/user/delete
Delete User

POST
/user/ban
Ban User

POST
/user/unban
Unban User

GET
/user/list
List Users

POST
/article/create
Create Article

POST
/article/save
Save Article

POST
/article/delete
Delete Article

POST
/article/send_for_approval
Send Article For Approval

POST
/article/draft
Draft Article

POST
/article/approve
Approve Article

POST
/article/deny
Deny Article

POST
/article/add_coauthor
Add Coathor

POST
/article/remove_coauthor
Remove Couathor

POST
/article/add_comment
Add Comment

POST
/article/remove_comment
Remove Comment

POST
/article/view
View Article

GET
/article/list
List Articles

GET
/article/list_newest_ten
List Newest Articles

GET
/article/get_pending
List Articles Pending Approval

GET
/article/get_authored
List Authored Articles

POST
/article/add_rating
Add Rating

POST
/topic/create
Create Topic

POST
/topic/delete
Delete Topic

POST
/topic/add_article
Add Article To Topic

POST
/topic/remove_article
Remove Article From Topic

GET
/topic/list
List Topics

POST
/article/search
Search Articles

GET
/whoami
Read Users Me
