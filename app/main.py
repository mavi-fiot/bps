#app/main

import os
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

# ⬇️ Завантаження змінних середовища з .env
load_dotenv()
IS_PROD = os.getenv("IS_PROD", "False") == "True"
DOMAIN = os.getenv("DOMAIN", "https://your-domain.com")

# 🔌 Імпорт демо-роуту (шифрування)
from kzp.secure_vote_api import router as secure_vote_router

# 🛠 Перевірка необхідних директорій
if not os.path.exists("static"):
    os.makedirs("static")
if not os.path.exists("templates"):
    raise RuntimeError("❌ Шаблони templates/ не знайдено!")

# 📦 Створення FastAPI-застосунку
app = FastAPI(
    title="ІСЕГ — Інформаційна Система Електронного Голосування",
    version="1.0.0",
    description="Система для проведення захищених електронних засідань із шифруванням та підписом бюлетенів"
)

# 🧩 Дозволити CORS (відкритий у dev, обмежений у продакшн)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if not IS_PROD else [DOMAIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 📂 Статичні файли
app.mount("/static", StaticFiles(directory="static"), name="static")

# 🧾 Шаблони
templates = Jinja2Templates(directory="templates")

# 🔌 Підключення роутерів
app.include_router(secure_vote_router, prefix="/secure", tags=["Захист голосу"])

# 📋 Головна сторінка
@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "title": "ІСЕГ — Електронне голосування"
    })

