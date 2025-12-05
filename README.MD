# XShorts

XShorts is a lightweight Vine-inspired looping video platform. The FastAPI backend included here supports:

- Account creation and login with bearer tokens
- Video uploads (stored on disk), looping playback flag, and rich metadata, served statically from `/media`
- Global and following feeds ordered by creation time
- Likes, comments, and "revines" (re-shares) to echo Vine's engagement model
- Following/follower relationships and simple profile summaries

## Running locally
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the API server:
   ```bash
   uvicorn app.main:app --reload
   ```
3. Open the built-in UI at `http://127.0.0.1:8000/` for quick testing, or use the interactive API docs at `http://127.0.0.1:8000/docs`.

## API quickstart
- Register or log in to receive a bearer token:
  ```bash
  curl -X POST http://127.0.0.1:8000/auth/register -H "Content-Type: application/json" \
    -d '{"username": "demo", "password": "demo"}'
  ```
- Upload a looping video:
  ```bash
  curl -X POST http://127.0.0.1:8000/videos/upload \
    -H "Authorization: Bearer <token>" \
    -F "description=First loop" \
    -F "file=@path/to/video.mp4"
  ```
- Browse feeds:
  - Global feed: `GET /videos/feed`
  - Following feed: `GET /users/me/following/feed`
- Engage:
  - Like/unlike: `POST /videos/{id}/like` and `DELETE /videos/{id}/like`
  - Comments: `POST /videos/{id}/comments`
  - Revine: `POST /videos/{id}/revine`
  - Follow/unfollow: `POST`/`DELETE /users/{userId}/follow`
  - Profile: `GET /users/{userId}/profile` or `GET /users/me/profile` for your own summary

Data is stored in `xshorts.db` (SQLite). Uploaded videos are saved to the `media/` directory, which is git-ignored.
placeholder
