import secrets
import shutil
from datetime import datetime
from pathlib import Path
from typing import Annotated, List, Optional

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi import status
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext
from sqlmodel import Field, Session, SQLModel, UniqueConstraint, create_engine, select

APP_NAME = "XShorts"
DATABASE_URL = "sqlite:///./xshorts.db"
MEDIA_ROOT = Path("media")
MEDIA_ROOT.mkdir(parents=True, exist_ok=True)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Models
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    password_hash: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuthToken(SQLModel, table=True):
    token: str = Field(primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Video(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    owner_id: int = Field(foreign_key="user.id")
    description: Optional[str] = Field(default=None, max_length=300)
    video_path: str
    loop: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Follow(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("follower_id", "followee_id", name="follow_unique"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    follower_id: int = Field(foreign_key="user.id")
    followee_id: int = Field(foreign_key="user.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Like(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("user_id", "video_id", name="like_unique"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    video_id: int = Field(foreign_key="video.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Comment(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    video_id: int = Field(foreign_key="video.id")
    text: str = Field(max_length=500)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Revine(SQLModel, table=True):
    __table_args__ = (UniqueConstraint("user_id", "video_id", name="revine_unique"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    video_id: int = Field(foreign_key="video.id")
    note: Optional[str] = Field(default=None, max_length=280)
    created_at: datetime = Field(default_factory=datetime.utcnow)


# Schemas
class UserCreate(SQLModel):
    username: str
    password: str


class TokenResponse(SQLModel):
    token: str
    username: str


class VideoResponse(SQLModel):
    id: int
    owner_id: int
    description: Optional[str]
    video_path: str
    loop: bool
    created_at: datetime
    likes: int
    comments: int
    revines: int


class CommentCreate(SQLModel):
    text: str


class CommentResponse(SQLModel):
    id: int
    user_id: int
    video_id: int
    text: str
    created_at: datetime


class ProfileResponse(SQLModel):
    id: int
    username: str
    created_at: datetime
    followers: int
    following: int
    uploads: List[VideoResponse]


# Utilities

def create_db_and_tables() -> None:
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def get_user_from_token(session: Session, token: str) -> User:
    db_token = session.exec(select(AuthToken).where(AuthToken.token == token)).first()
    if not db_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = session.get(User, db_token.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid user")
    return user


def current_user(session: SessionDep, token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    return get_user_from_token(session, token)


CurrentUser = Annotated[User, Depends(current_user)]


app = FastAPI(title=APP_NAME, description="A fast, looping video platform inspired by Vine.")
app.mount("/media", StaticFiles(directory=MEDIA_ROOT), name="media")


@app.get("/", response_class=HTMLResponse)
def landing_page():
    return HTMLResponse(
        """
        <!doctype html>
        <html lang=\"en\">
        <head>
          <meta charset=\"utf-8\" />
          <title>XShorts</title>
          <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
          <style>
            :root { color-scheme: light dark; font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }
            body { margin: 0 auto; max-width: 1000px; padding: 24px; line-height: 1.5; }
            header { display: flex; align-items: center; gap: 12px; }
            h1 { margin: 0; }
            form { margin-bottom: 12px; }
            section { margin-bottom: 24px; padding: 12px; border: 1px solid #5553; border-radius: 12px; }
            input, button, textarea { font: inherit; padding: 8px; }
            .stack { display: flex; flex-direction: column; gap: 8px; }
            .row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
            .card { border: 1px solid #5553; border-radius: 10px; padding: 12px; margin-bottom: 12px; }
            video { max-width: 100%; border-radius: 8px; }
            .meta { font-size: 12px; opacity: 0.8; display: flex; gap: 12px; }
            #status { font-weight: 600; }
          </style>
        </head>
        <body>
          <header>
            <h1>📹 XShorts</h1>
            <div id=\"status\"></div>
          </header>

          <section>
            <h2>Register / Login</h2>
            <div class=\"row\">
              <input id=\"username\" placeholder=\"username\" />
              <input id=\"password\" placeholder=\"password\" type=\"password\" />
              <button onclick=\"register()\">Register</button>
              <button onclick=\"login()\">Login</button>
              <button onclick=\"logout()\">Logout</button>
            </div>
            <div class=\"meta\" id=\"userInfo\"></div>
          </section>

          <section>
            <h2>Upload</h2>
            <div class=\"stack\">
              <input id=\"description\" placeholder=\"Description (optional)\" />
              <div class=\"row\">
                <input type=\"file\" id=\"file\" accept=\"video/*\" />
                <label><input type=\"checkbox\" id=\"loop\" checked /> Loop</label>
                <button onclick=\"upload()\">Upload</button>
              </div>
            </div>
          </section>

          <section>
            <div class=\"row\">
              <h2 style=\"margin-right:auto\">Feed</h2>
              <button onclick=\"loadFeed()\">Refresh</button>
            </div>
            <div id=\"feed\"></div>
          </section>

          <script>
            const api = '';
            let token = localStorage.getItem('token') || '';
            const statusEl = document.getElementById('status');
            const userInfo = document.getElementById('userInfo');

            function setStatus(message) {
              statusEl.textContent = message || '';
            }

            function setUser(username) {
              if (username) {
                userInfo.textContent = `Logged in as ${username}`;
              } else {
                userInfo.textContent = '';
              }
            }

            async function register() {
              const username = document.getElementById('username').value;
              const password = document.getElementById('password').value;
              const resp = await fetch(`${api}/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
              });
              const data = await resp.json();
              if (!resp.ok) { setStatus(data.detail || 'Register failed'); return; }
              token = data.token;
              localStorage.setItem('token', token);
              setUser(data.username);
              setStatus('Registered');
              loadFeed();
            }

            async function login() {
              const username = document.getElementById('username').value;
              const password = document.getElementById('password').value;
              const resp = await fetch(`${api}/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
              });
              const data = await resp.json();
              if (!resp.ok) { setStatus(data.detail || 'Login failed'); return; }
              token = data.token;
              localStorage.setItem('token', token);
              setUser(data.username);
              setStatus('Logged in');
              loadFeed();
            }

            function logout() {
              token = '';
              localStorage.removeItem('token');
              setUser('');
              setStatus('Logged out');
            }

            async function upload() {
              if (!token) { setStatus('Login first'); return; }
              const file = document.getElementById('file').files[0];
              if (!file) { setStatus('Pick a video'); return; }
              const form = new FormData();
              form.append('description', document.getElementById('description').value);
              form.append('loop', document.getElementById('loop').checked);
              form.append('file', file);
              const resp = await fetch(`${api}/videos/upload`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` },
                body: form
              });
              const data = await resp.json();
              if (!resp.ok) { setStatus(data.detail || 'Upload failed'); return; }
              setStatus('Uploaded');
              document.getElementById('file').value = '';
              loadFeed();
            }

            async function loadFeed() {
              const resp = await fetch(`${api}/videos/feed`);
              const data = await resp.json();
              if (!resp.ok) { setStatus('Feed failed'); return; }
              const target = document.getElementById('feed');
              target.innerHTML = '';
              if (data.length === 0) { target.textContent = 'No videos yet. Upload one!'; return; }
              data.forEach(v => {
                const card = document.createElement('div');
                card.className = 'card';
                const video = document.createElement('video');
                video.src = `/${v.video_path}`;
                video.controls = true;
                video.loop = v.loop;
                const title = document.createElement('div');
                title.textContent = v.description || 'Untitled';
                const meta = document.createElement('div');
                meta.className = 'meta';
                meta.textContent = `❤️ ${v.likes} · 💬 ${v.comments} · 🔄 ${v.revines}`;
                card.appendChild(video);
                card.appendChild(title);
                card.appendChild(meta);
                target.appendChild(card);
              });
            }

            if (token) { setStatus('Token loaded'); loadFeed(); } else { setStatus('Welcome'); loadFeed(); }
          </script>
        </body>
        </html>
        """
    )


# Auth routes
@app.post("/auth/register", response_model=TokenResponse)
def register(payload: UserCreate, session: SessionDep):
    existing = session.exec(select(User).where(User.username == payload.username)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")

    user = User(username=payload.username, password_hash=hash_password(payload.password))
    session.add(user)
    session.commit()
    session.refresh(user)

    token = AuthToken(token=secrets.token_urlsafe(32), user_id=user.id)
    session.add(token)
    session.commit()
    return TokenResponse(token=token.token, username=user.username)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: UserCreate, session: SessionDep):
    user = session.exec(select(User).where(User.username == payload.username)).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = AuthToken(token=secrets.token_urlsafe(32), user_id=user.id)
    session.add(token)
    session.commit()
    return TokenResponse(token=token.token, username=user.username)


# Video endpoints
@app.post("/videos/upload", response_model=VideoResponse)
def upload_video(
    description: Optional[str] = None,
    loop: bool = True,
    file: UploadFile = File(...),
    session: SessionDep = Depends(),
    user: CurrentUser = Depends(),
):
    if not file.content_type.startswith("video/"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only video uploads are allowed")

    filename = f"{secrets.token_hex(8)}_{Path(file.filename).name}"
    destination = MEDIA_ROOT / filename
    with destination.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    video = Video(owner_id=user.id, description=description, video_path=str(destination), loop=loop)
    session.add(video)
    session.commit()
    session.refresh(video)

    return enrich_video(session, video)


@app.get("/videos/feed", response_model=List[VideoResponse])
def global_feed(limit: int = 20, session: SessionDep = Depends()):
    videos = session.exec(select(Video).order_by(Video.created_at.desc()).limit(limit)).all()
    return [enrich_video(session, v) for v in videos]


@app.get("/videos/{video_id}", response_model=VideoResponse)
def video_detail(video_id: int, session: SessionDep = Depends()):
    video = session.get(Video, video_id)
    if not video:
        raise HTTPException(status_code=404, detail="Video not found")
    return enrich_video(session, video)


@app.post("/videos/{video_id}/like")
def like_video(video_id: int, session: SessionDep = Depends(), user: CurrentUser = Depends()):
    video = session.get(Video, video_id)
    if not video:
        raise HTTPException(status_code=404, detail="Video not found")

    existing = session.exec(
        select(Like).where(Like.user_id == user.id, Like.video_id == video_id)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Already liked")

    session.add(Like(user_id=user.id, video_id=video_id))
    session.commit()
    return {"status": "liked"}


@app.delete("/videos/{video_id}/like")
def unlike_video(video_id: int, session: SessionDep = Depends(), user: CurrentUser = Depends()):
    like = session.exec(select(Like).where(Like.user_id == user.id, Like.video_id == video_id)).first()
    if not like:
        raise HTTPException(status_code=404, detail="Like not found")
    session.delete(like)
    session.commit()
    return {"status": "unliked"}


@app.post("/videos/{video_id}/comments", response_model=CommentResponse)
def add_comment(
    video_id: int,
    payload: CommentCreate,
    session: SessionDep = Depends(),
    user: CurrentUser = Depends(),
):
    video = session.get(Video, video_id)
    if not video:
        raise HTTPException(status_code=404, detail="Video not found")

    comment = Comment(user_id=user.id, video_id=video_id, text=payload.text)
    session.add(comment)
    session.commit()
    session.refresh(comment)
    return comment


@app.get("/videos/{video_id}/comments", response_model=List[CommentResponse])
def list_comments(video_id: int, session: SessionDep = Depends()):
    video = session.get(Video, video_id)
    if not video:
        raise HTTPException(status_code=404, detail="Video not found")
    comments = session.exec(
        select(Comment).where(Comment.video_id == video_id).order_by(Comment.created_at)
    ).all()
    return comments


@app.post("/videos/{video_id}/revine")
def revine_video(
    video_id: int,
    note: Optional[str] = None,
    session: SessionDep = Depends(),
    user: CurrentUser = Depends(),
):
    video = session.get(Video, video_id)
    if not video:
        raise HTTPException(status_code=404, detail="Video not found")

    already_revined = session.exec(
        select(Revine).where(Revine.user_id == user.id, Revine.video_id == video_id)
    ).first()
    if already_revined:
        raise HTTPException(status_code=400, detail="Already revined")

    revine = Revine(user_id=user.id, video_id=video_id, note=note)
    session.add(revine)
    session.commit()
    return {"status": "revined"}


@app.get("/users/me/following/feed", response_model=List[VideoResponse])
def following_feed(limit: int = 20, session: SessionDep = Depends(), user: CurrentUser = Depends()):
    followees = session.exec(select(Follow.followee_id).where(Follow.follower_id == user.id)).all()
    if not followees:
        return []

    videos = session.exec(
        select(Video)
        .where(Video.owner_id.in_(followees))
        .order_by(Video.created_at.desc())
        .limit(limit)
    ).all()
    return [enrich_video(session, v) for v in videos]


@app.post("/users/{user_id}/follow")
def follow_user(user_id: int, session: SessionDep = Depends(), user: CurrentUser = Depends()):
    if user_id == user.id:
        raise HTTPException(status_code=400, detail="Cannot follow yourself")

    target = session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    existing = session.exec(
        select(Follow).where(Follow.follower_id == user.id, Follow.followee_id == user_id)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Already following")

    session.add(Follow(follower_id=user.id, followee_id=user_id))
    session.commit()
    return {"status": "following"}


@app.delete("/users/{user_id}/follow")
def unfollow_user(user_id: int, session: SessionDep = Depends(), user: CurrentUser = Depends()):
    follow = session.exec(
        select(Follow).where(Follow.follower_id == user.id, Follow.followee_id == user_id)
    ).first()
    if not follow:
        raise HTTPException(status_code=404, detail="Follow relationship not found")
    session.delete(follow)
    session.commit()
    return {"status": "unfollowed"}


@app.get("/users/{user_id}/profile")
def user_profile(user_id: int, session: SessionDep = Depends()):
    target = session.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    follower_count = session.exec(select(Follow).where(Follow.followee_id == user_id)).all()
    following_count = session.exec(select(Follow).where(Follow.follower_id == user_id)).all()
    uploads = session.exec(select(Video).where(Video.owner_id == user_id)).all()

    return ProfileResponse(
        id=target.id,
        username=target.username,
        created_at=target.created_at,
        followers=len(follower_count),
        following=len(following_count),
        uploads=[enrich_video(session, v) for v in uploads],
    )


@app.get("/users/me/profile", response_model=ProfileResponse)
def current_user_profile(session: SessionDep = Depends(), user: CurrentUser = Depends()):
    return user_profile(user.id, session)


# Helpers

def enrich_video(session: Session, video: Video) -> VideoResponse:
    likes = session.exec(select(Like).where(Like.video_id == video.id)).all()
    comments = session.exec(select(Comment).where(Comment.video_id == video.id)).all()
    revines = session.exec(select(Revine).where(Revine.video_id == video.id)).all()

    return VideoResponse(
        id=video.id,
        owner_id=video.owner_id,
        description=video.description,
        video_path=video.video_path,
        loop=video.loop,
        created_at=video.created_at,
        likes=len(likes),
        comments=len(comments),
        revines=len(revines),
    )


@app.on_event("startup")
def on_startup():
    create_db_and_tables()

