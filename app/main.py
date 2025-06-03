# app/main.py

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# 🔌 Імпорт демо-роуту (шифрування)
from kzp.secure_vote_api import router as secure_vote_router

# 📦 Створення FastAPI-застосунку
app = FastAPI(
    title="ІСЕГ — Інформаційна Система Електронного Голосування",
    version="1.0.0",
    description="Система для проведення захищених електронних засідань із шифруванням та підписом бюлетенів"
)

# 🧩 Дозволити CORS (можна обмежити на проді)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ❗ У production обмежити доменами
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 📂 Статичні файли
app.mount("/static", StaticFiles(directory="static"), name="static")

# 🧾 Шаблони (наприклад, Jinja2)
templates = Jinja2Templates(directory="templates")

# 🔌 Підключення роутерів
app.include_router(secure_vote_router, prefix="/secure", tags=["Захист голосу"])

# 📋 Головна сторінка (тимчасово-заглушка)
@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "ІСЕГ — Електронне голосування"
    })
