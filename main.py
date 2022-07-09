from datetime import datetime, timedelta
import requests, os, psycopg2, json
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# openssl rand -hex 32
SECRET_KEY = ""
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

conn = psycopg2.connect(database="server_db", user="postgres", password="postgres", host="localhost", port="5432")
cursor = conn.cursor()

cursor.execute(f"SELECT * FROM public.users")
userlist = list(cursor.fetchall())
user_db = {}
for rawuser in userlist:
	user = {}
	user["id"] = str(rawuser[0])
	user["username"] = str(rawuser[1])
	user["hashed_password"] = str(rawuser[2])
	user["banned"] = str(rawuser[3])
	uid = user["id"]
	cursor.execute(f"SELECT role_id FROM public.user_roles WHERE uid='{uid}'", (str(uid)))
	role_ids = list(cursor.fetchall())
	roles = []
	for role_id in role_ids:
		cursor.execute(f"SELECT role_name FROM public.roles WHERE role_id='{role_id[0]}'", (str(role_id[0])))
		roles.append(cursor.fetchall()[0][0])
	user["roles"] = roles
	user_db[user["username"]] = user


class Token(BaseModel):
	access_token: str
	token_type: str


class TokenData(BaseModel):
	username: str | None = None


class User(BaseModel):
	id: str
	username: str
	roles: list | None = None
	banned: bool


class UserInDB(User):
	hashed_password: str


class SignupForm(BaseModel):
	username: str
	password: str

class RoleChangeForm(BaseModel):
	username: str
	role: str

class UsernameOnly(BaseModel):
	username: str

class Article(BaseModel):
	article_id: str
	title: str | None = None
	text: str | None = None

class NewArticle(BaseModel):
	title: str
	text: str | None = None

class ArticleId(BaseModel):
	article_id: str

class ArticleUserPair(ArticleId):
	uid: str

class ArticleComment(ArticleId):
	text: str

class ArticleRating(ArticleId):
	text: str
	stars: int

class ArticleCommentId(ArticleId):
	comment_id: str

class Topic(BaseModel):
	name: str

class TopicArticleIds(BaseModel):
	article_id: str
	topic_id: str

class SearchForm(BaseModel):
	sortby: str
	query: str | None = None
	reverse: bool

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()

def rolename_to_roleid(rolename):
	cursor.execute(f"SELECT role_id FROM public.roles WHERE role_name='{rolename}'")
	result = list(cursor.fetchall())
	if len(result) > 0:
		return result[0][0]
	return False

def roleid_to_rolename(roleid):
	cursor.execute(f"SELECT role_name FROM public.roles WHERE role_id='{roleid}'")
	result = list(cursor.fetchall())
	if len(result) > 0:
		return result[0][0]
	return False

def username_to_uid(username):
	cursor.execute(f"SELECT uid FROM public.users WHERE username='{username}'")
	result = list(cursor.fetchall())
	if len(result) > 0:
		return result[0][0]
	return False

def topic_name_to_topic_id(name):
	cursor.execute(f"SELECT topic_id FROM public.topics WHERE name='{name}'")
	result = list(cursor.fetchall())
	if len(result) > 0:
		return result[0][0]
	return False


def uid_to_username(uid):
	cursor.execute(f"SELECT username FROM public.users WHERE uid='{uid}'")
	result = list(cursor.fetchall())
	if len(result) > 0:
		return result[0][0]
	return False

def verify_password(plain_password, hashed_password):
	return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
	return pwd_context.hash(password)


def get_user(db, username: str):
	if username in db:
		user_dict = db[username]
		return UserInDB(**user_dict)


def authenticate_user(db, username: str, password: str):
	user = get_user(db, username)
	if not user:
		return False
	if not verify_password(password, user.hashed_password):
		return False
	return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
	to_encode = data.copy()
	if expires_delta:
		expire = datetime.utcnow() + expires_delta
	else:
		expire = datetime.utcnow() + timedelta(minutes=15)
	to_encode.update({"exp": expire})
	encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
	return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
	credentials_exception = HTTPException(
		status_code=status.HTTP_401_UNAUTHORIZED,
		detail="Could not validate credentials",
		headers={"WWW-Authenticate": "Bearer"},
	)
	try:
		payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
		username: str = payload.get("sub")
		if username is None:
			raise credentials_exception
		token_data = TokenData(username=username)
	except JWTError:
		raise credentials_exception
	user = get_user(user_db, username=token_data.username)
	if user is None:
		raise credentials_exception
	return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
	if current_user.banned:
		raise HTTPException(status_code=HTTP_401_UNAUTHORIZED, detail="Banned user")
	return current_user

def is_writer(uid, article_id):
	cursor.execute(f"SELECT * FROM public.article_writers WHERE uid='{uid}' AND article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) > 0:
		return True
	return False



@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
	user = authenticate_user(user_db, form_data.username, form_data.password)
	if not user:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Incorrect username or password",
			headers={"WWW-Authenticate": "Bearer"},
		)
	access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
	access_token = create_access_token(
		data={"sub": user.username}, expires_delta=access_token_expires
	)
	return {"access_token": access_token, "token_type": "bearer"}


@app.post("/user/sign_up", status_code=status.HTTP_201_CREATED)
async def sign_up(user: SignupForm):
	username = user.username
	password = user.password
	if username == '' or password == '':
		raise HTTPException(status_code=417, detail="Empty fields in request")
	else:
		cursor.execute(f"SELECT * FROM public.users WHERE username='{username}'", (str(username)))
		result = list(cursor.fetchall())
		if len(result) > 0:
			raise HTTPException(status_code=409, detail="User already exists")
		else:
			hashed_pass = get_password_hash(password)
			cursor.execute(f"INSERT INTO public.users (username, password, ban) VALUES ('{username}', '{hashed_pass}', {False})")
			conn.commit()
			cursor.execute(f"SELECT * FROM public.users WHERE username='{username}'", (str(username)))
			result = list(cursor.fetchall())
			cursor.execute(f"INSERT INTO public.user_roles (uid, role_id) VALUES ('{result[0][0]}', '1')")
			conn.commit()
			return {username: username}


@app.post("/user/assign_role", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: RoleChangeForm, current_user: User = Depends(get_current_active_user)):
	if not "Admin" in current_user.roles:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	username = inputForm.username
	rolename = inputForm.role
	uid = username_to_uid(username)
	roleid = rolename_to_roleid(rolename)
	if not (roleid and uid):
		raise HTTPException(status_code=404, detail="User, role or both does not exist")
	cursor.execute(f"SELECT * FROM public.user_roles WHERE uid={uid} AND role_id={roleid}")
	result = list(cursor.fetchall())
	if len(result) > 0:
		raise HTTPException(status_code=409, detail="User already has this role")
	cursor.execute(f"INSERT INTO public.user_roles (uid, role_id) VALUES ('{uid}', '{roleid}')")
	conn.commit()
	return {username:current_user.username}

@app.post("/user/unassign_role", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: RoleChangeForm, current_user: User = Depends(get_current_active_user)):
	if not "Admin" in current_user.roles:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	username = inputForm.username
	rolename = inputForm.role
	uid = username_to_uid(username)
	roleid = rolename_to_roleid(rolename)
	if not (roleid and uid):
		raise HTTPException(status_code=404, detail="User, role or both does not exist")
	cursor.execute(f"SELECT * FROM public.user_roles WHERE uid='{uid}' AND role_id='{roleid}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=409, detail="User already does not have this role")
	cursor.execute(f"DELETE FROM public.user_roles WHERE uid='{uid}' AND role_id='{roleid}'")
	conn.commit()
	return {username:current_user.username}


@app.post("/user/delete", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: UsernameOnly, current_user: User = Depends(get_current_active_user)):
	if not "Admin" in current_user.roles:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	username = inputForm.username
	uid = username_to_uid(username)
	if not uid:
		raise HTTPException(status_code=404, detail="User does not exist")
	cursor.execute(f"DELETE FROM public.user_roles WHERE uid='{uid}'")
	conn.commit()
	cursor.execute(f"DELETE FROM public.article_writers WHERE uid='{uid}'")
	conn.commit()
	cursor.execute(f"DELETE FROM public.users WHERE uid='{uid}'")
	conn.commit()
	return {username:current_user.username}


@app.post("/user/ban", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: UsernameOnly, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Moderator" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	username = inputForm.username
	uid = username_to_uid(username)
	if not uid:
		raise HTTPException(status_code=404, detail="User does not exist")
	cursor.execute(f"SELECT * FROM public.users WHERE uid='{uid}' AND ban='True'")
	result = list(cursor.fetchall())
	if len(result) > 0:
		raise HTTPException(status_code=409, detail="User is already banned")
	cursor.execute(f"UPDATE public.users SET ban='True' WHERE uid='{uid}'")
	conn.commit()
	return {username:current_user.username}

@app.post("/user/unban", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: UsernameOnly, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Moderator" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	username = inputForm.username
	uid = username_to_uid(username)
	if not uid:
		raise HTTPException(status_code=404, detail="User does not exist")
	cursor.execute(f"SELECT * FROM public.users WHERE uid='{uid}' AND ban='False'")
	result = list(cursor.fetchall())
	if len(result) > 0:
		raise HTTPException(status_code=409, detail="User is not banned")
	cursor.execute(f"UPDATE public.users SET ban='False' WHERE uid='{uid}'")
	conn.commit()
	return {username:current_user.username}


@app.get("/user/list", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(current_user: User = Depends(get_current_active_user)):
	users = []
	cursor.execute(f"SELECT uid, username, ban FROM public.users")
	result = list(cursor.fetchall())
	for entry in result:
		user = {}
		user["id"] = entry[0]
		user["username"] = entry[1]
		user["banned_status"] = entry[2]
		users.append(user)
	return {"users":users}



@app.post("/article/create", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: NewArticle, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Author" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	conn.commit()
	cursor.execute(f"SELECT * FROM public.articles WHERE title='{inputForm.title}' AND text='{inputForm.text}'")
	result = list(cursor.fetchall())
	if len(result) > 0:
		raise HTTPException(status_code=409, detail="This exact article already exists")
	cursor.execute(f"INSERT INTO public.articles(title, text, status) VALUES ('{inputForm.title}', '{inputForm.text}', 'draft')")
	conn.commit()
	cursor.execute(f"SELECT * FROM public.articles WHERE title='{inputForm.title}' AND text='{inputForm.text}' AND status='draft'")
	result = list(cursor.fetchall())
	cursor.execute(f"INSERT INTO public.article_writers(article_id, uid) VALUES ('{result[0][0]}', '{current_user.id}')")
	conn.commit()
	return {"username":current_user.username}

@app.post("/article/save", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: Article, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Author" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	if not result[0][3] == "draft":
		raise HTTPException(status_code=405, detail="Wrong status for editing")
	if inputForm.title:
		cursor.execute(f"UPDATE public.articles SET title='{inputForm.title}' WHERE article_id='{article_id}'")
		conn.commit()
	if inputForm.text:
		cursor.execute(f"UPDATE public.articles SET text='{inputForm.text}' WHERE article_id='{article_id}'")
		conn.commit()
	return {"username":current_user.username}

@app.post("/article/delete", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleId, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Author" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	cursor.execute(f"DELETE FROM public.topic_articles WHERE article_id='{article_id}'")
	conn.commit()
	cursor.execute(f"DELETE FROM public.articles WHERE article_id='{article_id}'")
	conn.commit()
	return {"username":current_user.username}

@app.post("/article/send_for_approval", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleId, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Author" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	if not is_writer(current_user.id, inputForm.article_id) and not "Admin" in current_user.roles:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	cursor.execute(f"UPDATE public.articles SET status='Approving' WHERE article_id='{article_id}'")
	conn.commit()
	return {"username":current_user.username}

@app.post("/article/draft", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleId, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Author" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	if not is_writer(current_user.id, inputForm.article_id) and not "Admin" in current_user.roles:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	cursor.execute(f"UPDATE public.articles SET status='draft' WHERE article_id='{article_id}'")
	conn.commit()
	return {"username":current_user.username}

@app.post("/article/approve", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleId, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Moderator" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	cursor.execute(f"UPDATE public.articles SET status='Approved', publish_time='{datetime.now()}' WHERE article_id='{article_id}'")
	conn.commit()
	return {"username":current_user.username}


@app.post("/article/deny", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleId, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Moderator" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	cursor.execute(f"UPDATE public.articles SET status='Denied' WHERE article_id='{article_id}'")
	conn.commit()
	return {"username":current_user.username}


@app.post("/article/add_coauthor", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleUserPair, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Author" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	uid = inputForm.uid
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	cursor.execute(f"SELECT * FROM public.users WHERE uid='{uid}'")
	result2 = list(cursor.fetchall())
	if len(result2) == 0:
		raise HTTPException(status_code=404, detail="User doesn't exist")
	if not is_writer(current_user.id, inputForm.article_id) and not "Admin" in current_user.roles:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	cursor.execute(f"INSERT INTO public.article_writers(article_id, uid) VALUES ('{result[0][0]}', '{result2[0][0]}')")
	conn.commit()
	return {"username":current_user.username}

@app.post("/article/remove_coauthor", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleUserPair, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Author" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	uid = inputForm.uid
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	cursor.execute(f"SELECT * FROM public.users WHERE uid='{uid}'")
	result2 = list(cursor.fetchall())
	if len(result2) == 0:
		raise HTTPException(status_code=404, detail="User doesn't exist")
	if not is_writer(current_user.id, inputForm.article_id) and not "Admin" in current_user.roles:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	cursor.execute(f"DELETE FROM public.article_writers WHERE article_id='{result[0][0]}' AND uid='{result2[0][0]}'")
	conn.commit()
	return {"username":current_user.username}


@app.post("/article/add_comment", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleComment, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Reader" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	text = inputForm.text
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	cursor.execute(f"INSERT INTO public.comments(c_text) VALUES ('{text}')")
	conn.commit()
	cursor.execute(f"SELECT * FROM public.comments WHERE c_text='{text}'")
	result2 = list(cursor.fetchall())
	cursor.execute(f"INSERT INTO public.article_comments(article_id, comment_id) VALUES ('{result[0][0]}', '{result2[0][0]}')")
	conn.commit()
	return {"username":current_user.username}

@app.post("/article/remove_comment", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleCommentId, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Moderator" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	comment_id = inputForm.comment_id
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	cursor.execute(f"SELECT * FROM public.comments WHERE comment_id='{comment_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Comment doesn't exist")
	cursor.execute(f"SELECT * FROM public.article_comments WHERE article_id='{article_id}' AND comment_id='{comment_id}'")
	result2 = list(cursor.fetchall())
	cursor.execute(f"DELETE FROM public.article_comments WHERE article_id='{article_id}' AND comment_id='{comment_id}'")
	conn.commit()
	cursor.execute(f"DELETE FROM public.comments WHERE comment_id='{comment_id}'")
	conn.commit()
	return {"username":current_user.username}


@app.post("/article/view", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleId, current_user: User = Depends(get_current_active_user)):
	article_id = inputForm.article_id
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	article = result[0]
	if not ("Admin" in current_user.roles or ("Author" in current_user.roles and is_writer(current_user.id, article[0])) or ("Moderator" in current_user.roles and article[3] == 'Approving') or ("Reader" in current_user.roles and article[3] == 'Approved')):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	cursor.execute(f"SELECT comment_id FROM public.article_comments WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	comments = []
	for tmp in result:
		comment_id = tmp[0]
		cursor.execute(f"SELECT * FROM public.comments WHERE comment_id='{comment_id}'")
		result2 = list(cursor.fetchall())
		comments.append(result2[0])
	return {"article": article, "comments": comments}

@app.get("/article/list", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	articles = []
	cursor.execute(f"SELECT article_id, title, text, status, publish_time FROM public.articles")
	result = list(cursor.fetchall())
	for entry in result:
		article = {}
		article["id"] = entry[0]
		article["title"] = entry[1]
		article["text"] = entry[2]
		article["status"] = entry[3]
		article["publish_time"] = entry[4]
		articles.append(article)
	return {"articles": articles}

@app.get("/article/list_newest_ten", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Reader" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	articles = []
	cursor.execute(f"SELECT article_id, title, text, status, publish_time FROM public.articles")
	result = list(cursor.fetchall())
	for entry in result:
		article = {}
		article["id"] = entry[0]
		article["title"] = entry[1]
		article["text"] = entry[2]
		article["status"] = entry[3]
		article["publish_time"] = entry[4]
		if article["publish_time"]:
			articles.append(article)
	articles_sorted = sorted(articles, key=lambda article: article["publish_time"], reverse=True)
	send_articles = []
	ratings = []
	for i in range(min(10, len(articles_sorted))):
		send_articles.append(articles_sorted[i])
	for article in send_articles:
		cursor.execute(f"SELECT rating_id FROM public.article_ratings WHERE article_id='{article['id']}'")
		result = list(cursor.fetchall())
		total = 0
		for entry in result:
			cursor.execute(f"SELECT stars FROM public.ratings WHERE rating_id='{entry[0]}'")
			result2 = list(cursor.fetchall())
			total = total + float(result2[0][0])
		if len(result) > 0:
			rating = total / len(result)
		else:
			rating = None
		ratings.append(rating)
	return {"articles": send_articles, "ratings": ratings}

@app.get("/article/get_pending", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	articles = []
	cursor.execute(f"SELECT article_id, title, text, status, publish_time FROM public.articles WHERE status='Approving'")
	result = list(cursor.fetchall())
	for entry in result:
		article = {}
		article["id"] = entry[0]
		article["title"] = entry[1]
		article["text"] = entry[2]
		article["status"] = entry[3]
		article["publish_time"] = entry[4]
		articles.append(article)
	return {"articles": articles}

@app.get("/article/get_authored", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Author" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	articles = []
	cursor.execute(f"SELECT article_id, title, text, status, publish_time FROM public.articles")
	result = list(cursor.fetchall())
	cursor.execute(f"SELECT article_id FROM public.article_writers WHERE uid='{current_user.id}'")
	result2 = list(cursor.fetchall())
	articleIds = []
	for entry in result2:
		articleIds.append(result2[0][0])
	print(articleIds)
	for entry in result:
		if not entry[0] in articleIds:
			continue
		article = {}
		article["id"] = entry[0]
		article["title"] = entry[1]
		article["text"] = entry[2]
		article["status"] = entry[3]
		article["publish_time"] = entry[4]
		articles.append(article)
	return {"articles": articles}


@app.post("/article/add_rating", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: ArticleRating, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles or "Reader" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	cursor.execute(f"SELECT rating_id FROM public.article_ratings WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	cursor.execute(f"SELECT rating_id FROM public.ratings WHERE uid='{current_user.id}'")
	result2 = list(cursor.fetchall())
	for entry in result:
		for entry2 in result2:
			if entry[0] == entry2[0]:
				raise HTTPException(status_code=409, detail="You already voted for this article")
	stars = inputForm.stars
	text = inputForm.text
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	cursor.execute(f"INSERT INTO public.ratings(r_text, stars, uid) VALUES ('{text}', '{stars}', '{current_user.id}')")
	conn.commit()
	cursor.execute(f"SELECT * FROM public.ratings WHERE r_text='{text}'")
	result2 = list(cursor.fetchall())
	cursor.execute(f"INSERT INTO public.article_ratings(article_id, rating_id) VALUES ('{result[0][0]}', '{result2[0][0]}')")
	conn.commit()
	return {"username":current_user.username}


@app.post("/topic/create", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: Topic, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	name = inputForm.name
	cursor.execute(f"SELECT * FROM public.topics WHERE name='{name}'")
	result = list(cursor.fetchall())
	if len(result) > 0:
		raise HTTPException(status_code=409, detail="Topic already exists")
	cursor.execute(f"INSERT INTO public.topics(name) VALUES ('{name}')")
	conn.commit()
	return {"username":current_user.username}

@app.post("/topic/delete", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: Topic, current_user: User = Depends(get_current_active_user)):
	if not "Admin" in current_user.roles:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	name = inputForm.name
	topic_id = topic_name_to_topic_id(name)
	if not topic_id:
		raise HTTPException(status_code=404, detail="Topic does not exist")
	cursor.execute(f"DELETE FROM public.topic_articles WHERE topic_id='{topic_id}'")
	conn.commit()
	cursor.execute(f"DELETE FROM public.topics WHERE topic_id='{topic_id}'")
	conn.commit()
	return {"username":current_user.username}

@app.post("/topic/add_article", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: TopicArticleIds, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	topic_id = inputForm.topic_id
	
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	
	cursor.execute(f"SELECT * FROM public.topics WHERE topic_id='{topic_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Topic doesn't exist")
	
	cursor.execute(f"SELECT * FROM public.topic_articles WHERE article_id='{article_id}' AND topic_id='{topic_id}'")
	result = list(cursor.fetchall())
	if len(result) > 1:
		raise HTTPException(status_code=409, detail="Article is already part of the topic")
	cursor.execute(f"INSERT INTO public.topic_articles(article_id, topic_id) VALUES ('{article_id}', '{topic_id}')")
	conn.commit()
	return {"username":current_user.username}

@app.post("/topic/remove_article", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: TopicArticleIds, current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	article_id = inputForm.article_id
	topic_id = inputForm.topic_id
	
	cursor.execute(f"SELECT * FROM public.articles WHERE article_id='{article_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Article doesn't exist")
	
	cursor.execute(f"SELECT * FROM public.topics WHERE topic_id='{topic_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=404, detail="Topic doesn't exist")
	
	cursor.execute(f"SELECT * FROM public.topic_articles WHERE article_id='{article_id}' AND topic_id='{topic_id}'")
	result = list(cursor.fetchall())
	if len(result) == 0:
		raise HTTPException(status_code=409, detail="Article is already not a part of the topic")
	cursor.execute(f"DELETE FROM public.topic_articles WHERE article_id='{article_id}' AND topic_id='{topic_id}'")
	conn.commit()
	return {"username":current_user.username}

@app.get("/topic/list", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(current_user: User = Depends(get_current_active_user)):
	if not ("Admin" in current_user.roles):
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail="Access denied",
			headers={"WWW-Authenticate": "Bearer"},
		)
	topics = []
	cursor.execute(f"SELECT * FROM public.topics")
	result = list(cursor.fetchall())
	for entry in result:
		topic = {}
		topic["id"] = entry[0]
		topic["name"] = entry[1]
		topics.append(topic)
	return {"topics": topics}

@app.post("/article/search", status_code=status.HTTP_202_ACCEPTED)
async def assign_role(inputForm: SearchForm, current_user: User = Depends(get_current_active_user)):
	articles = []
	cursor.execute(f"SELECT article_id, title, text, status, publish_time FROM public.articles WHERE status='Approved'")
	result = list(cursor.fetchall())
	for entry in result:
		article = {}
		article["id"] = entry[0]
		article["title"] = entry[1]
		article["text"] = entry[2]
		article["status"] = entry[3]
		article["publish_time"] = entry[4]
		articles.append(article)
	articles_sorted = []
	if inputForm.sortby in ["text","title","publish_time"]:
		articles_sorted = sorted(articles, key=lambda article: article[inputForm.sortby], reverse=inputForm.reverse)
	elif inputForm.sortby == "rating":
		for article in articles:
			cursor.execute(f"SELECT rating_id FROM public.article_ratings WHERE article_id='{article['id']}'")
			result = list(cursor.fetchall())
			total = 0
			for entry in result:
				cursor.execute(f"SELECT stars FROM public.ratings WHERE rating_id='{entry[0]}'")
				result2 = list(cursor.fetchall())
				total = total + float(result2[0][0])
			if len(result) > 0:
				rating = total / len(result)
			else:
				rating = None
			article["rating"] = rating
		articles_sorted = sorted(articles, key=lambda article: article[inputForm.sortby], reverse=inputForm.reverse)
	else:
		raise HTTPException(status_code=405, detail="Wrong sorting method")
	articles_final = []
	if inputForm.query:
		for article in articles_sorted:
			cursor.execute(f"SELECT uid FROM public.article_writers WHERE article_id='{article['id']}'")
			result1 = list(cursor.fetchall())
			author_arr = []
			for entry in result1:
				cursor.execute(f"SELECT username FROM public.users WHERE uid='{entry[0]}'")
				result3 = list(cursor.fetchall())
				author_arr.append(result3[0][0])
			article["authors"] = author_arr
		articles_sorted = sorted(articles, key=lambda article: article[inputForm.sortby], reverse=inputForm.reverse)
		for article in articles_sorted:
			if inputForm.query in article["title"] or inputForm.query in article["text"] or inputForm.query in article["authors"]:
				articles_final.append(article)
	else: 
		articles_final = articles_sorted
	return {"sorted": articles_final}

@app.get("/whoami", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
	return current_user