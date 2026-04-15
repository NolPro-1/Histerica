import json
import os
import random
import re
import secrets
import threading
import time
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
USERS_PATH = BASE_DIR / "users.json"
DATA_PATH = BASE_DIR / "data.json"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "qwerty")
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png"}
ALLOWED_3D_EXTENSIONS = {".glb"}
ALLOWED_AUDIO_EXTENSIONS = {".mp3", ".ogg", ".wav"}
ARTIFACT_PRICES = {"common": 50, "rare": 100, "epic": 250, "leg": 500, "legendary": 500}
COOLDOWN_SECONDS = 10 * 60  # 10 minutes
_users_lock = threading.Lock()
_data_lock = threading.Lock()

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))


@app.route("/")
def index():
    return render_template("index.html")


def load_users():
    with _users_lock:
        if not USERS_PATH.exists():
            return []
        with USERS_PATH.open("r", encoding="utf-8") as file:
            return json.load(file)


def save_users(users):
    with _users_lock:
        with USERS_PATH.open("w", encoding="utf-8") as file:
            json.dump(users, file, ensure_ascii=False, indent=2)


def load_data():
    with _data_lock:
        if not DATA_PATH.exists():
            return {"museums": [], "artifacts": []}
        with DATA_PATH.open("r", encoding="utf-8") as file:
            return json.load(file)


def save_data(data):
    with _data_lock:
        with DATA_PATH.open("w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)


def check_cooldown(user, artifact_id):
    """Return (on_cooldown: bool, remaining: int). Clears expired cooldowns."""
    failures = user.get("artifact_failures", {})
    fail_time = failures.get(str(artifact_id))
    if fail_time:
        elapsed = time.time() - fail_time
        if elapsed < COOLDOWN_SECONDS:
            return True, int(COOLDOWN_SECONDS - elapsed)
        del failures[str(artifact_id)]
    return False, 0


def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def allowed_3d_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_3D_EXTENSIONS


def allowed_audio_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_AUDIO_EXTENSIONS


def verify_password(stored, provided):
    """Compare password - supports both old plain text and new hashed passwords."""
    if stored.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(stored, provided)
    # Plain text fallback for legacy passwords — will be rehashed on login
    return False


def rehash_if_needed(user, plain_password):
    """Rehash password if stored in plain text."""
    if not user["password"].startswith(("pbkdf2:", "scrypt:")):
        user["password"] = generate_password_hash(plain_password)
        return True
    return False


def get_session_user():
    """Get current authenticated user nickname from session."""
    return session.get("user")


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_session_user():
            return jsonify({"error": "Требуется авторизация."}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify({"error": "Требуется доступ администратора."}), 403
        return f(*args, **kwargs)
    return decorated


def save_uploaded_image(file_obj, folder, filename):
    target_dir = BASE_DIR / "static" / "source" / folder
    target_dir.mkdir(parents=True, exist_ok=True)
    file_obj.save(target_dir / filename)
    return f"source/{folder}/{filename}"


def dms_to_decimal(degrees, minutes, seconds, direction):
    value = float(degrees)
    value += float(minutes or 0) / 60
    value += float((seconds or "0").replace(",", ".")) / 3600
    sign = -1 if direction in {"S", "Ю", "W", "З"} else 1
    return sign * value


def find_museum(data, museum_id):
    return next((museum for museum in data.get("museums", []) if museum.get("id") == museum_id), None)


def parse_coordinates(raw_value):
    value = str(raw_value or "").strip()
    if not value:
        return None

    normalized = value.upper().replace("Ё", "Е")
    dms_pattern = re.compile(
        r"(\d{1,3})\s*[°º]\s*(\d{1,2})?\s*[\'′]?\s*(\d{1,2}(?:[.,]\d+)?)?\s*[\"″]?\s*([NSEWСЮВЗ])"
    )
    dms_matches = dms_pattern.findall(normalized)
    if len(dms_matches) >= 2:
        lat = dms_to_decimal(*dms_matches[0])
        lon = dms_to_decimal(*dms_matches[1])
        return round(lat, 7), round(lon, 7)

    numeric_values = []
    for chunk in re.findall(r"[-+]?\d+(?:[.,]\d+)?", value):
        try:
            numeric_values.append(float(chunk.replace(",", ".")))
        except ValueError:
            continue
    if len(numeric_values) >= 2:
        return round(numeric_values[0], 7), round(numeric_values[1], 7)
    return None


@app.route("/api/register", methods=["POST"])
def register():
    payload = request.get_json(silent=True) or {}
    nickname = str(payload.get("nickname", "")).strip()
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", "")).strip()

    if not nickname:
        return jsonify({"error": "Введите никнейм."}), 400
    if not email or "@" not in email:
        return jsonify({"error": "Проверьте корректность почты."}), 400
    if len(password) < 8 or not password.isalnum():
        return jsonify(
            {
                "error": "Пароль должен быть не меньше 8 символов и содержать только латинские буквы и цифры."
            }
        ), 400

    users = load_users()
    if any(user["nickname"].lower() == nickname.lower() for user in users):
        return jsonify({"error": "Никнейм уже занят."}), 400
    if any(user["email"].lower() == email for user in users):
        return jsonify({"error": "Аккаунт с такой почтой уже существует."}), 400

    masked_email = email
    if "@" in email:
        name, domain = email.split("@", 1)
        masked_name = name[:-5] + "*****" if len(name) > 5 else "*****"
        masked_email = f"{masked_name}@{domain}"
    user_profile = {
        "museums_completed": 0,
        "artifacts_found": 0,
        "rating": 0,
        "coins": 0,
        "email_masked": masked_email,
        "two_factor_enabled": False,
    }
    users.append(
        {
            "nickname": nickname,
            "email": email,
            "password": generate_password_hash(password),
            "profile": user_profile,
            "inventory": {"skins": [], "items": [], "achievements": []},
            "artifact_failures": {},
        }
    )
    save_users(users)
    session["user"] = nickname
    return jsonify(
        {
            "success": True,
            "profile": user_profile,
            "nickname": nickname,
            "inventory": {"skins": [], "items": [], "achievements": []},
        }
    )


@app.route("/api/settings/email", methods=["POST"])
def change_email():
    payload = request.get_json(silent=True) or {}
    nickname = str(payload.get("nickname", "")).strip()
    password = str(payload.get("password", "")).strip()
    new_email = str(payload.get("new_email", "")).strip().lower()

    if not nickname or not password or not new_email:
        return jsonify({"error": "Заполните все поля."}), 400
    if "@" not in new_email:
        return jsonify({"error": "Некорректный email."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404
    if not verify_password(user["password"], password):
        return jsonify({"error": "Неверный пароль."}), 400
    if any(u["email"].lower() == new_email and u["nickname"] != nickname for u in users):
        return jsonify({"error": "Этот email уже занят."}), 400

    user["email"] = new_email
    local, domain = new_email.split("@", 1)
    masked = local[:3] + "*" * max(0, len(local) - 3) + "@" + domain
    user.setdefault("profile", {})["email_masked"] = masked
    save_users(users)
    return jsonify({"success": True, "email_masked": masked})


@app.route("/api/settings/password", methods=["POST"])
def change_password():
    payload = request.get_json(silent=True) or {}
    nickname = str(payload.get("nickname", "")).strip()
    old_password = str(payload.get("old_password", "")).strip()
    new_password = str(payload.get("new_password", "")).strip()
    confirm_password = str(payload.get("confirm_password", "")).strip()

    if not nickname or not old_password or not new_password or not confirm_password:
        return jsonify({"error": "Заполните все поля."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404
    if not verify_password(user["password"], old_password):
        return jsonify({"error": "Неверный старый пароль."}), 400
    if new_password != confirm_password:
        return jsonify({"error": "Пароли не совпадают."}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Минимум 8 символов."}), 400

    user["password"] = generate_password_hash(new_password)
    save_users(users)
    return jsonify({"success": True})


@app.route("/api/login", methods=["POST"])
def login():
    payload = request.get_json(silent=True) or {}
    identity = str(payload.get("identity", "")).strip().lower()
    password = str(payload.get("password", "")).strip()

    users = load_users()
    user = next(
        (
            u
            for u in users
            if u["nickname"].lower() == identity or u["email"].lower() == identity
        ),
        None,
    )
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 400
    # Plain text legacy check + rehash
    stored = user["password"]
    is_legacy = not stored.startswith(("pbkdf2:", "scrypt:"))
    if is_legacy:
        if stored != password:
            return jsonify({"error": "Неверный пароль."}), 400
        user["password"] = generate_password_hash(password)
    else:
        if not check_password_hash(stored, password):
            return jsonify({"error": "Неверный пароль."}), 400
    # Ensure artifact_failures exists for old users
    if "artifact_failures" not in user:
        user["artifact_failures"] = {}
    # Ensure coins exists for old users
    if "coins" not in user.get("profile", {}):
        user.setdefault("profile", {})["coins"] = 0
    save_users(users)
    session["user"] = user["nickname"]
    return jsonify(
        {
            "success": True,
            "nickname": user["nickname"],
            "profile": user.get("profile", {}),
            "inventory": resolve_inventory(user),
        }
    )


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    payload = request.get_json(silent=True) or {}
    password = str(payload.get("password", "")).strip()
    if password != ADMIN_PASSWORD:
        return jsonify({"error": "Неверный пароль администратора."}), 400
    session["is_admin"] = True
    return jsonify({"success": True})


@app.route("/api/admin/data", methods=["GET"])
def admin_data():
    return jsonify(load_data())


@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    users = load_users()
    return jsonify([{"nickname": u["nickname"]} for u in users])


@app.route("/api/admin/give-item", methods=["POST"])
def admin_give_item():
    payload = request.get_json(silent=True) or {}
    nickname = str(payload.get("nickname", "")).strip()
    item_type = str(payload.get("type", "")).strip()
    item_id = payload.get("item_id")

    if not nickname or not item_type:
        return jsonify({"error": "Не переданы данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    inv = user.setdefault("inventory", {"skins": [], "items": [], "achievements": []})

    if item_type == "artifact":
        if not item_id:
            return jsonify({"error": "Не указан артефакт."}), 400
        try:
            item_id = int(item_id)
        except (ValueError, TypeError):
            return jsonify({"error": "Некорректный ID артефакта."}), 400
        data_json = load_data()
        artifact = next((a for a in data_json["artifacts"] if a["id"] == item_id), None)
        if not artifact:
            return jsonify({"error": "Артефакт не найден."}), 404
        if item_id not in inv.setdefault("items", []):
            inv["items"].append(item_id)
            user["profile"]["artifacts_found"] = user.get("profile", {}).get("artifacts_found", 0) + 1
        else:
            return jsonify({"error": "Артефакт уже в инвентаре."}), 400
    elif item_type == "coins":
        amount = payload.get("amount", 0)
        try:
            amount = int(amount)
        except (ValueError, TypeError):
            return jsonify({"error": "Некорректное количество."}), 400
        if amount <= 0:
            return jsonify({"error": "Количество должно быть > 0."}), 400
        user.setdefault("profile", {})["coins"] = user.get("profile", {}).get("coins", 0) + amount
    else:
        return jsonify({"error": "Неизвестный тип предмета."}), 400

    save_users(users)
    return jsonify({"success": True})


@app.route("/api/museums", methods=["GET"])
def list_museums():
    data = load_data()
    return jsonify(data.get("museums", []))


@app.route("/api/admin/museums", methods=["POST"])
def admin_create_museum():
    name = str(request.form.get("name", "")).strip()
    address = str(request.form.get("address", "")).strip()
    city = str(request.form.get("city", "")).strip() or "Севастополь"
    description = str(request.form.get("description", "")).strip()
    coordinates = str(request.form.get("coordinates", "")).strip()
    parsed_coordinates = parse_coordinates(coordinates)
    photo = request.files.get("photo")
    location_map = request.files.get("location_map")

    if not name:
        return jsonify({"error": "Введите название музея."}), 400
    if not address:
        return jsonify({"error": "Введите адрес музея."}), 400
    if not city:
        return jsonify({"error": "Введите город музея."}), 400
    if coordinates and not parsed_coordinates:
        return jsonify({"error": "Введите координаты в формате: 44.6182, 33.5254 или 44°37′06″ с. ш. 33°31′27″ в. д."}), 400
    if not photo or not allowed_file(photo.filename):
        return jsonify({"error": "Загрузите изображение музея .jpg или .png."}), 400

    if location_map and location_map.filename and not allowed_file(location_map.filename):
        return jsonify({"error": "Карта локации должна быть .jpg или .png."}), 400

    data = load_data()
    museum_id = max((item.get("id", 0) for item in data.get("museums", [])), default=0) + 1

    photo_extension = Path(secure_filename(photo.filename)).suffix.lower()
    museum_image_path = save_uploaded_image(photo, "museum", f"{museum_id}{photo_extension}")

    map_image_path = f"source/maps/{museum_id}.png"
    if location_map and location_map.filename:
        map_extension = Path(secure_filename(location_map.filename)).suffix.lower()
        map_image_path = save_uploaded_image(location_map, "maps", f"{museum_id}{map_extension}")

    latitude = parsed_coordinates[0] if parsed_coordinates else None
    longitude = parsed_coordinates[1] if parsed_coordinates else None

    data["museums"].append(
        {
            "id": museum_id,
            "name": name,
            "description": description,
            "address": address,
            "city": city,
            "coordinates": coordinates,
            "latitude": latitude,
            "longitude": longitude,
            "map_image": map_image_path,
            "artifacts": [],
            "image": museum_image_path,
        }
    )
    save_data(data)
    return jsonify({"success": True, "museum": data["museums"][-1]})


@app.route("/api/admin/museums/<int:museum_id>", methods=["PUT"])
def admin_update_museum(museum_id):
    name = str(request.form.get("name", "")).strip()
    description = str(request.form.get("description", "")).strip()
    address = str(request.form.get("address", "")).strip()
    city = str(request.form.get("city", "")).strip() or "Севастополь"
    coordinates = str(request.form.get("coordinates", "")).strip()
    parsed_coordinates = parse_coordinates(coordinates) if coordinates else None
    photo = request.files.get("photo")
    location_map = request.files.get("location_map")

    if not name:
        return jsonify({"error": "Введите название музея."}), 400
    if not address:
        return jsonify({"error": "Введите адрес музея."}), 400
    if not city:
        return jsonify({"error": "Введите город музея."}), 400
    if coordinates and not parsed_coordinates:
        return jsonify({"error": "Некорректный формат координат."}), 400
    if photo and photo.filename and not allowed_file(photo.filename):
        return jsonify({"error": "Загрузите изображение музея .jpg или .png."}), 400
    if location_map and location_map.filename and not allowed_file(location_map.filename):
        return jsonify({"error": "Карта локации должна быть .jpg или .png."}), 400

    data = load_data()
    museum = find_museum(data, museum_id)
    if not museum:
        return jsonify({"error": "Музей не найден."}), 404

    museum["name"] = name
    museum["description"] = description
    museum["address"] = address
    museum["city"] = city
    museum["coordinates"] = coordinates
    museum["latitude"] = parsed_coordinates[0] if parsed_coordinates else None
    museum["longitude"] = parsed_coordinates[1] if parsed_coordinates else None

    if photo and photo.filename:
        extension = Path(secure_filename(photo.filename)).suffix.lower()
        museum["image"] = save_uploaded_image(photo, "museum", f"{museum_id}{extension}")

    if location_map and location_map.filename:
        map_extension = Path(secure_filename(location_map.filename)).suffix.lower()
        museum["map_image"] = save_uploaded_image(location_map, "maps", f"{museum_id}{map_extension}")

    save_data(data)
    return jsonify({"success": True, "museum": museum})


@app.route("/api/admin/museums/<int:museum_id>", methods=["DELETE"])
def admin_delete_museum(museum_id):
    data = load_data()
    museum = find_museum(data, museum_id)
    if not museum:
        return jsonify({"error": "Музей не найден."}), 404

    data["museums"] = [item for item in data.get("museums", []) if item.get("id") != museum_id]
    data["artifacts"] = [item for item in data.get("artifacts", []) if item.get("museum_id") != museum_id]
    save_data(data)
    return jsonify({"success": True})


@app.route("/api/admin/artifacts", methods=["POST"])
def admin_create_artifact():
    name = str(request.form.get("name", "")).strip()
    museum_id = request.form.get("museum_id")
    difficulty = str(request.form.get("difficulty", "")).strip()
    minigame = str(request.form.get("minigame", "words")).strip()
    map_x = request.form.get("map_x")
    map_y = request.form.get("map_y")
    quiz_questions = request.form.get("quiz_questions")
    words_data_raw = request.form.get("words_data")
    image = request.files.get("image")
    model_3d = request.files.get("model_3d")
    if not name:
        return jsonify({"error": "Введите название артефакта."}), 400
    if not museum_id:
        return jsonify({"error": "Выберите музей."}), 400
    if not difficulty:
        return jsonify({"error": "Введите сложность."}), 400
    if not image or not allowed_file(image.filename):
        return jsonify({"error": "Загрузите изображение .jpg или .png."}), 400
    if model_3d and model_3d.filename and not allowed_3d_file(model_3d.filename):
        return jsonify({"error": "3D-модель должна быть в формате .glb."}), 400
    try:
        museum_id = int(museum_id)
    except ValueError:
        return jsonify({"error": "Некорректный ID музея."}), 400

    parsed_x = None
    parsed_y = None
    if map_x is not None and str(map_x).strip() != "":
        try:
            parsed_x = float(str(map_x).replace(",", "."))
        except ValueError:
            return jsonify({"error": "Некорректная координата X."}), 400
    if map_y is not None and str(map_y).strip() != "":
        try:
            parsed_y = float(str(map_y).replace(",", "."))
        except ValueError:
            return jsonify({"error": "Некорректная координата Y."}), 400
    if parsed_x is not None and not 0 <= parsed_x <= 100:
        return jsonify({"error": "Координата X должна быть в диапазоне 0..100."}), 400
    if parsed_y is not None and not 0 <= parsed_y <= 100:
        return jsonify({"error": "Координата Y должна быть в диапазоне 0..100."}), 400

    quiz_data = None
    if minigame == "quiz" and quiz_questions:
        try:
            quiz_data = json.loads(quiz_questions)
            if not isinstance(quiz_data, list) or len(quiz_data) == 0:
                return jsonify({"error": "Некорректные данные квиза."}), 400
            for q in quiz_data:
                if not isinstance(q, dict) or "type" not in q or "question" not in q:
                    return jsonify({"error": "Некорректный формат вопроса."}), 400
                if q["type"] == "test":
                    if "correct_answer" not in q or "wrong_answers" not in q or len(q["wrong_answers"]) != 3:
                        return jsonify({"error": "Некорректный тестовый вопрос."}), 400
                elif q["type"] == "open":
                    if "answer" not in q:
                        return jsonify({"error": "Некорректный открытый вопрос."}), 400
        except json.JSONDecodeError:
            return jsonify({"error": "Некорректный JSON квиза."}), 400
    data = load_data()
    if not any(museum["id"] == museum_id for museum in data["museums"]):
        return jsonify({"error": "Музей не найден."}), 400
    artifact_id = len(data["artifacts"]) + 1
    extension = Path(secure_filename(image.filename)).suffix.lower()
    filename = f"{museum_id}_{artifact_id}{extension}"
    target_dir = BASE_DIR / "static" / "source" / "artefacts"
    target_dir.mkdir(parents=True, exist_ok=True)
    image.save(target_dir / filename)
    image_path = f"source/artefacts/{filename}"
    model_path = None
    if model_3d and model_3d.filename:
        model_path = save_uploaded_image(model_3d, "models", f"{museum_id}_{artifact_id}.glb")

    artifact = {
        "id": artifact_id,
        "name": name,
        "museum_id": museum_id,
        "difficulty": difficulty,
        "minigame": minigame,
        "map_x": parsed_x,
        "map_y": parsed_y,
        "image": image_path,
        "model_3d": model_path,
    }
    if quiz_data:
        artifact["quiz_questions"] = quiz_data
    if words_data_raw:
        try:
            words_list = json.loads(words_data_raw)
            if isinstance(words_list, list) and len(words_list) > 0:
                artifact["words_data"] = words_list
        except json.JSONDecodeError:
            pass

    # Piano minigame fields
    if minigame == "piano":
        music_file = request.files.get("music")
        if music_file and music_file.filename and allowed_audio_file(music_file.filename):
            ext = Path(secure_filename(music_file.filename)).suffix.lower()
            music_name = f"{museum_id}_{artifact_id}{ext}"
            music_dir = BASE_DIR / "static" / "source" / "music"
            music_dir.mkdir(parents=True, exist_ok=True)
            music_file.save(music_dir / music_name)
            artifact["music"] = f"source/music/{music_name}"
        piano_bg_file = request.files.get("piano_bg")
        if piano_bg_file and piano_bg_file.filename and allowed_file(piano_bg_file.filename):
            bg_ext = Path(secure_filename(piano_bg_file.filename)).suffix.lower()
            bg_name = f"piano_bg_{museum_id}_{artifact_id}{bg_ext}"
            bg_dir = BASE_DIR / "static" / "source" / "piano_bg"
            bg_dir.mkdir(parents=True, exist_ok=True)
            piano_bg_file.save(bg_dir / bg_name)
            artifact["piano_bg"] = f"source/piano_bg/{bg_name}"
        beats_raw = request.form.get("piano_beats")
        if beats_raw:
            try:
                beats = json.loads(beats_raw)
                if isinstance(beats, list):
                    artifact["piano_beats"] = beats
            except json.JSONDecodeError:
                pass
        tile_speed_raw = request.form.get("tile_speed")
        if tile_speed_raw:
            try:
                artifact["tile_speed"] = max(1, min(20, float(tile_speed_raw)))
            except (ValueError, TypeError):
                artifact["tile_speed"] = 5
        difficulty_raw = request.form.get("song_difficulty")
        if difficulty_raw:
            try:
                artifact["song_difficulty"] = max(1, min(5, int(difficulty_raw)))
            except (ValueError, TypeError):
                artifact["song_difficulty"] = 3

    # Super Quiz minigame fields
    if minigame == "super_quiz":
        sq_bg_file = request.files.get("sq_bg")
        if sq_bg_file and sq_bg_file.filename and allowed_file(sq_bg_file.filename):
            ext = Path(secure_filename(sq_bg_file.filename)).suffix.lower()
            bg_name = f"sq_bg_{museum_id}_{artifact_id}{ext}"
            bg_dir = BASE_DIR / "static" / "source" / "sq_bg"
            bg_dir.mkdir(parents=True, exist_ok=True)
            sq_bg_file.save(bg_dir / bg_name)
            artifact["sq_bg"] = f"source/sq_bg/{bg_name}"
        sq_music_file = request.files.get("sq_music")
        if sq_music_file and sq_music_file.filename and allowed_audio_file(sq_music_file.filename):
            ext = Path(secure_filename(sq_music_file.filename)).suffix.lower()
            m_name = f"sq_music_{museum_id}_{artifact_id}{ext}"
            m_dir = BASE_DIR / "static" / "source" / "music"
            m_dir.mkdir(parents=True, exist_ok=True)
            sq_music_file.save(m_dir / m_name)
            artifact["sq_music"] = f"source/music/{m_name}"
        sq_char_file = request.files.get("sq_character")
        if sq_char_file and sq_char_file.filename and allowed_file(sq_char_file.filename):
            ext = Path(secure_filename(sq_char_file.filename)).suffix.lower()
            c_name = f"sq_char_{museum_id}_{artifact_id}{ext}"
            c_dir = BASE_DIR / "static" / "source" / "sq_chars"
            c_dir.mkdir(parents=True, exist_ok=True)
            sq_char_file.save(c_dir / c_name)
            artifact["sq_character"] = f"source/sq_chars/{c_name}"
        sq_char_name = request.form.get("sq_character_name", "").strip()
        if sq_char_name:
            artifact["sq_character_name"] = sq_char_name
        sq_questions_raw = request.form.get("sq_questions")
        if sq_questions_raw:
            try:
                sq_q = json.loads(sq_questions_raw)
                if isinstance(sq_q, list) and len(sq_q) > 0:
                    # Handle per-step photos
                    for i, step in enumerate(sq_q):
                        photo_file = request.files.get(f"sq_step_photo_{i}")
                        if photo_file and photo_file.filename and allowed_file(photo_file.filename):
                            ext = Path(secure_filename(photo_file.filename)).suffix.lower()
                            p_name = f"sq_step_{museum_id}_{artifact_id}_{i}{ext}"
                            p_dir = BASE_DIR / "static" / "source" / "sq_chars"
                            p_dir.mkdir(parents=True, exist_ok=True)
                            photo_file.save(p_dir / p_name)
                            step["photo"] = f"source/sq_chars/{p_name}"
                    artifact["sq_questions"] = sq_q
            except json.JSONDecodeError:
                pass

    data["artifacts"].append(artifact)
    for museum in data["museums"]:
        if museum["id"] == museum_id:
            museum.setdefault("artifacts", []).append(artifact_id)
            break
    save_data(data)
    return jsonify({"success": True, "artifact": artifact})


@app.route("/api/admin/artifacts/<int:artifact_id>", methods=["PUT"])
def admin_update_artifact(artifact_id):
    data = load_data()
    artifact = next((a for a in data.get("artifacts", []) if a["id"] == artifact_id), None)
    if not artifact:
        return jsonify({"error": "Артефакт не найден."}), 404

    name = str(request.form.get("name", "")).strip()
    difficulty = str(request.form.get("difficulty", "")).strip()
    minigame = str(request.form.get("minigame", "")).strip()
    map_x = request.form.get("map_x")
    map_y = request.form.get("map_y")
    quiz_questions = request.form.get("quiz_questions")
    words_data_raw = request.form.get("words_data")
    image = request.files.get("image")
    model_3d = request.files.get("model_3d")

    if name:
        artifact["name"] = name
    if difficulty:
        artifact["difficulty"] = difficulty
    if minigame:
        artifact["minigame"] = minigame

    if map_x is not None and str(map_x).strip() != "":
        try:
            px = float(str(map_x).replace(",", "."))
            if 0 <= px <= 100:
                artifact["map_x"] = px
        except ValueError:
            pass
    if map_y is not None and str(map_y).strip() != "":
        try:
            py = float(str(map_y).replace(",", "."))
            if 0 <= py <= 100:
                artifact["map_y"] = py
        except ValueError:
            pass

    if image and allowed_file(image.filename):
        extension = Path(secure_filename(image.filename)).suffix.lower()
        filename = f"{artifact['museum_id']}_{artifact_id}{extension}"
        target_dir = BASE_DIR / "static" / "source" / "artefacts"
        target_dir.mkdir(parents=True, exist_ok=True)
        image.save(target_dir / filename)
        artifact["image"] = f"source/artefacts/{filename}"

    if model_3d and model_3d.filename and allowed_3d_file(model_3d.filename):
        artifact["model_3d"] = save_uploaded_image(model_3d, "models", f"{artifact['museum_id']}_{artifact_id}.glb")

    if minigame == "quiz" and quiz_questions:
        try:
            quiz_data = json.loads(quiz_questions)
            if isinstance(quiz_data, list) and len(quiz_data) > 0:
                artifact["quiz_questions"] = quiz_data
        except json.JSONDecodeError:
            pass

    if minigame == "words" and words_data_raw:
        try:
            words_list = json.loads(words_data_raw)
            if isinstance(words_list, list) and len(words_list) > 0:
                artifact["words_data"] = words_list
        except json.JSONDecodeError:
            pass

    # Piano minigame fields (update)
    if minigame == "piano":
        music_file = request.files.get("music")
        if music_file and music_file.filename and allowed_audio_file(music_file.filename):
            ext = Path(secure_filename(music_file.filename)).suffix.lower()
            music_name = f"{artifact['museum_id']}_{artifact_id}{ext}"
            music_dir = BASE_DIR / "static" / "source" / "music"
            music_dir.mkdir(parents=True, exist_ok=True)
            music_file.save(music_dir / music_name)
            artifact["music"] = f"source/music/{music_name}"
        piano_bg_file = request.files.get("piano_bg")
        if piano_bg_file and piano_bg_file.filename and allowed_file(piano_bg_file.filename):
            bg_ext = Path(secure_filename(piano_bg_file.filename)).suffix.lower()
            bg_name = f"piano_bg_{artifact['museum_id']}_{artifact_id}{bg_ext}"
            bg_dir = BASE_DIR / "static" / "source" / "piano_bg"
            bg_dir.mkdir(parents=True, exist_ok=True)
            piano_bg_file.save(bg_dir / bg_name)
            artifact["piano_bg"] = f"source/piano_bg/{bg_name}"
        beats_raw = request.form.get("piano_beats")
        if beats_raw:
            try:
                beats = json.loads(beats_raw)
                if isinstance(beats, list):
                    artifact["piano_beats"] = beats
            except json.JSONDecodeError:
                pass
        tile_speed_raw = request.form.get("tile_speed")
        if tile_speed_raw:
            try:
                artifact["tile_speed"] = max(1, min(20, float(tile_speed_raw)))
            except (ValueError, TypeError):
                pass
        difficulty_raw = request.form.get("song_difficulty")
        if difficulty_raw:
            try:
                artifact["song_difficulty"] = max(1, min(5, int(difficulty_raw)))
            except (ValueError, TypeError):
                pass

    # Super Quiz minigame fields (update)
    if minigame == "super_quiz":
        sq_bg_file = request.files.get("sq_bg")
        if sq_bg_file and sq_bg_file.filename and allowed_file(sq_bg_file.filename):
            ext = Path(secure_filename(sq_bg_file.filename)).suffix.lower()
            bg_name = f"sq_bg_{artifact.get('museum_id',0)}_{artifact_id}{ext}"
            bg_dir = BASE_DIR / "static" / "source" / "sq_bg"
            bg_dir.mkdir(parents=True, exist_ok=True)
            sq_bg_file.save(bg_dir / bg_name)
            artifact["sq_bg"] = f"source/sq_bg/{bg_name}"
        sq_music_file = request.files.get("sq_music")
        if sq_music_file and sq_music_file.filename and allowed_audio_file(sq_music_file.filename):
            ext = Path(secure_filename(sq_music_file.filename)).suffix.lower()
            m_name = f"sq_music_{artifact.get('museum_id',0)}_{artifact_id}{ext}"
            m_dir = BASE_DIR / "static" / "source" / "music"
            m_dir.mkdir(parents=True, exist_ok=True)
            sq_music_file.save(m_dir / m_name)
            artifact["sq_music"] = f"source/music/{m_name}"
        sq_char_file = request.files.get("sq_character")
        if sq_char_file and sq_char_file.filename and allowed_file(sq_char_file.filename):
            ext = Path(secure_filename(sq_char_file.filename)).suffix.lower()
            c_name = f"sq_char_{artifact.get('museum_id',0)}_{artifact_id}{ext}"
            c_dir = BASE_DIR / "static" / "source" / "sq_chars"
            c_dir.mkdir(parents=True, exist_ok=True)
            sq_char_file.save(c_dir / c_name)
            artifact["sq_character"] = f"source/sq_chars/{c_name}"
        sq_char_name = request.form.get("sq_character_name", "").strip()
        if sq_char_name:
            artifact["sq_character_name"] = sq_char_name
        sq_questions_raw = request.form.get("sq_questions")
        if sq_questions_raw:
            try:
                sq_q = json.loads(sq_questions_raw)
                if isinstance(sq_q, list) and len(sq_q) > 0:
                    for i, step in enumerate(sq_q):
                        photo_file = request.files.get(f"sq_step_photo_{i}")
                        if photo_file and photo_file.filename and allowed_file(photo_file.filename):
                            ext = Path(secure_filename(photo_file.filename)).suffix.lower()
                            p_name = f"sq_step_{artifact.get('museum_id',0)}_{artifact_id}_{i}{ext}"
                            p_dir = BASE_DIR / "static" / "source" / "sq_chars"
                            p_dir.mkdir(parents=True, exist_ok=True)
                            photo_file.save(p_dir / p_name)
                            step["photo"] = f"source/sq_chars/{p_name}"
                    artifact["sq_questions"] = sq_q
            except json.JSONDecodeError:
                pass

    save_data(data)
    return jsonify({"success": True, "artifact": artifact})


@app.route("/api/admin/artifacts/<int:artifact_id>", methods=["DELETE"])
def admin_delete_artifact(artifact_id):
    data = load_data()
    artifact = next((a for a in data.get("artifacts", []) if a["id"] == artifact_id), None)
    if not artifact:
        return jsonify({"error": "Артефакт не найден."}), 404

    museum_id = artifact.get("museum_id")
    data["artifacts"] = [a for a in data["artifacts"] if a["id"] != artifact_id]

    for museum in data.get("museums", []):
        if museum["id"] == museum_id:
            museum["artifacts"] = [aid for aid in museum.get("artifacts", []) if aid != artifact_id]
            break

    save_data(data)
    return jsonify({"success": True})


@app.route("/api/profile/avatar", methods=["POST"])
def upload_avatar():
    # Получаем файл и никнейм из формы (или query, если потребуется)
    avatar = request.files.get("avatar")
    nickname = request.form.get("nickname") or request.args.get("nickname")
    if not avatar or not allowed_file(avatar.filename):
        return jsonify({"error": "Загрузите изображение .jpg или .png."}), 400
    if not nickname:
        # Можно доработать: брать ник из сессии, если будет авторизация
        return jsonify({"error": "Не передан никнейм пользователя."}), 400
    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404
    ext = Path(secure_filename(avatar.filename)).suffix.lower()
    filename = f"{nickname}{ext}"
    rel_path = save_uploaded_image(avatar, "avatar", filename)
    # Сохраняем путь к аватару в профиле пользователя
    user["profile"]["avatar"] = rel_path
    save_users(users)
    return jsonify({"success": True, "avatar": rel_path})


def mark_discovered(user, artifact_id):
    """Mark artifact as discovered forever (survives selling)."""
    discovered = user.setdefault("discovered_artifacts", [])
    if artifact_id not in discovered:
        discovered.append(artifact_id)


def resolve_inventory(user):
    """Resolve artifact IDs in inventory to full objects with name, image, museum, difficulty."""
    data_json = load_data()
    artifacts_map = {a["id"]: a for a in data_json.get("artifacts", [])}
    museums_map = {m["id"]: m for m in data_json.get("museums", [])}

    raw_items = user.get("inventory", {}).get("items", [])
    resolved = []
    for aid in raw_items:
        art = artifacts_map.get(aid)
        if not art:
            continue
        museum = museums_map.get(art.get("museum_id"))
        resolved.append({
            "id": art["id"],
            "name": art.get("name", "Артефакт"),
            "image": art.get("image", ""),
            "difficulty": art.get("difficulty", ""),
            "museum_name": museum["name"] if museum else "",
            "model_3d": art.get("model_3d", ""),
        })
    raw_rewards = user.get("inventory", {}).get("rewards", [])
    resolved_rewards = []
    for rid in raw_rewards:
        art = artifacts_map.get(rid)
        if not art:
            continue
        museum = museums_map.get(art.get("museum_id"))
        resolved_rewards.append({
            "id": art["id"],
            "name": art.get("name", "Артефакт"),
            "image": art.get("image", ""),
            "difficulty": art.get("difficulty", ""),
            "museum_name": museum["name"] if museum else "",
        })
    return {
        "skins": user.get("inventory", {}).get("skins", []),
        "items": resolved,
        "achievements": user.get("inventory", {}).get("achievements", []),
        "rewards": resolved_rewards,
        "discovered_artifacts": user.get("discovered_artifacts", []),
    }


@app.route("/api/inventory", methods=["GET"])
def get_inventory():
    """Return user's inventory with fully resolved artifact objects."""
    nickname = request.args.get("nickname")
    if not nickname:
        return jsonify({"error": "Не передан никнейм."}), 400
    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404
    result = resolve_inventory(user)
    inv = user.get("inventory", {})
    result["banners"] = inv.get("banners", [])
    result["frames"] = inv.get("frames", [])
    result["equipped_banner"] = user.get("profile", {}).get("equipped_banner", "")
    result["equipped_frame"] = user.get("profile", {}).get("equipped_frame", "")
    return jsonify(result)


@app.route("/api/claim-artifact", methods=["POST"])
def claim_artifact():
    data = request.get_json()
    artifact_id = data.get("artifact_id")
    nickname = data.get("nickname") or request.args.get("nickname")  # Пока без сессии
    if not artifact_id or not nickname:
        return jsonify({"error": "Не переданы данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    data_json = load_data()
    artifact = next((a for a in data_json["artifacts"] if a["id"] == artifact_id), None)
    if not artifact:
        return jsonify({"error": "Артефакт не найден."}), 404

    # Add to inventory
    if artifact_id not in user["inventory"]["items"]:
        user["inventory"]["items"].append(artifact_id)
        user["profile"]["artifacts_found"] += 1
    mark_discovered(user, artifact_id)

    save_users(users)
    return jsonify({"success": True})


@app.route("/api/artifact-status", methods=["GET"])
def artifact_status():
    """Check if artifact is on cooldown after failure"""
    artifact_id = request.args.get("artifact_id")
    nickname = get_session_user() or request.args.get("nickname")

    if not artifact_id or not nickname:
        return jsonify({"error": "Не переданы данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    if "artifact_failures" not in user:
        user["artifact_failures"] = {}

    on_cd, remaining = check_cooldown(user, artifact_id)
    if on_cd:
        return jsonify({"on_cooldown": True, "remaining_time": remaining})

    save_users(users)
    return jsonify({"on_cooldown": False})


@app.route("/api/quiz-check", methods=["POST"])
def quiz_check():
    """Check quiz answers and award artifact if correct"""
    data = request.get_json()
    artifact_id = data.get("artifact_id")
    nickname = data.get("nickname")
    answers = data.get("answers", [])  # Array of {question_index, answer}
    
    if not artifact_id or not nickname:
        return jsonify({"error": "Не переданы данные."}), 400
    
    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404
    
    data_json = load_data()
    artifact = next((a for a in data_json["artifacts"] if a["id"] == artifact_id), None)
    if not artifact:
        return jsonify({"error": "Артефакт не найден."}), 404
    
    # Get quiz questions
    quiz_questions = artifact.get("quiz_questions", [])
    if isinstance(quiz_questions, str):
        try:
            quiz_questions = json.loads(quiz_questions)
        except:
            return jsonify({"error": "Ошибка в квизе артефакта."}), 400
    
    if not quiz_questions:
        return jsonify({"error": "Квиз не найден."}), 400
    
    # Check answers
    correct_count = 0
    for answer_data in answers:
        question_index = answer_data.get("question_index", -1)
        user_answer = str(answer_data.get("answer", "")).strip().lower()
        
        if 0 <= question_index < len(quiz_questions):
            question = quiz_questions[question_index]
            if question.get("type") == "open":
                correct_answer = str(question.get("answer", "")).strip().lower()
                if user_answer == correct_answer:
                    correct_count += 1
            elif question.get("type") == "test":
                correct_answer = str(question.get("correct_answer", "")).strip().lower()
                if user_answer == correct_answer:
                    correct_count += 1
    
    # Check if passed (80%)
    total_questions = len(quiz_questions)
    required_correct = max(1, int(total_questions * 0.8))
    passed = correct_count >= required_correct
    
    if passed:
        # Add to inventory
        if artifact_id not in user["inventory"]["items"]:
            user["inventory"]["items"].append(artifact_id)
            user["profile"]["artifacts_found"] += 1
        mark_discovered(user, artifact_id)
        
        # Ensure artifact_failures exists
        if "artifact_failures" not in user:
            user["artifact_failures"] = {}
        
        # Remove any existing cooldown
        if str(artifact_id) in user["artifact_failures"]:
            del user["artifact_failures"][str(artifact_id)]

        # Achievement tracking
        if correct_count == total_questions:
            user["_quiz_perfect"] = True
            advance_daily_quest(user, "quiz_perfect")
        advance_daily_quest(user, "collect")
        advance_daily_quest(user, "play")
        new_achs = check_achievements(user)
        
        save_users(users)
        return jsonify({
            "success": True,
            "passed": True,
            "correct": correct_count,
            "total": total_questions,
            "new_achievements": new_achs
        })
    else:
        # Failed - set cooldown
        if "artifact_failures" not in user:
            user["artifact_failures"] = {}
        
        user["artifact_failures"][str(artifact_id)] = time.time()
        save_users(users)
        
        return jsonify({
            "success": True,
            "passed": False,
            "correct": correct_count,
            "total": total_questions
        })


@app.route("/api/superquiz-check", methods=["POST"])
def superquiz_check():
    """Check super quiz answers and award trophy artifact"""
    data = request.get_json()
    artifact_id = data.get("artifact_id")
    nickname = data.get("nickname")
    answers = data.get("answers", [])

    if not artifact_id or not nickname:
        return jsonify({"error": "Не переданы данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    data_json = load_data()
    artifact = next((a for a in data_json["artifacts"] if a["id"] == artifact_id), None)
    if not artifact:
        return jsonify({"error": "Артефакт не найден."}), 404

    sq_questions = artifact.get("sq_questions", [])
    if not sq_questions:
        return jsonify({"error": "Квиз не найден."}), 400

    # Count only answerable steps (test / open)
    answerable = [s for s in sq_questions if s.get("type") in ("test", "open")]
    correct_count = 0
    for ans in answers:
        idx = ans.get("step_index", -1)
        user_answer = str(ans.get("answer", "")).strip().lower()
        if 0 <= idx < len(sq_questions):
            step = sq_questions[idx]
            if step.get("type") == "test":
                if user_answer == str(step.get("correct_answer", "")).strip().lower():
                    correct_count += 1
            elif step.get("type") == "open":
                if user_answer == str(step.get("answer", "")).strip().lower():
                    correct_count += 1

    total = len(answerable)
    required = max(1, int(total * 0.8)) if total > 0 else 0
    passed = correct_count >= required

    if passed:
        user.setdefault("inventory", {"items": [], "skins": []})
        user["inventory"].setdefault("rewards", [])
        if artifact_id not in user["inventory"]["rewards"]:
            user["inventory"]["rewards"].append(artifact_id)
        if artifact_id not in user["inventory"]["items"]:
            user["inventory"]["items"].append(artifact_id)
            user["profile"]["artifacts_found"] += 1
        mark_discovered(user, artifact_id)

        if "artifact_failures" not in user:
            user["artifact_failures"] = {}
        if str(artifact_id) in user["artifact_failures"]:
            del user["artifact_failures"][str(artifact_id)]

        new_achs = check_achievements(user)
        save_users(users)
        return jsonify({
            "success": True,
            "passed": True,
            "correct": correct_count,
            "total": total,
            "new_achievements": new_achs
        })
    else:
        if "artifact_failures" not in user:
            user["artifact_failures"] = {}
        user["artifact_failures"][str(artifact_id)] = time.time()
        save_users(users)
        return jsonify({
            "success": True,
            "passed": False,
            "correct": correct_count,
            "total": total
        })


@app.route("/api/words-complete", methods=["POST"])
def words_complete():
    """Award artifact after words minigame completion"""
    data = request.get_json()
    artifact_id = data.get("artifact_id")
    nickname = get_session_user() or data.get("nickname")

    if not artifact_id or not nickname:
        return jsonify({"error": "Не переданы данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    on_cd, remaining = check_cooldown(user, artifact_id)
    if on_cd:
        return jsonify({"error": "Артефакт на кулдауне.", "remaining_time": remaining}), 400

    data_json = load_data()
    artifact = next((a for a in data_json["artifacts"] if a["id"] == artifact_id), None)
    if not artifact:
        return jsonify({"error": "Артефакт не найден."}), 404

    if artifact_id not in user["inventory"]["items"]:
        user["inventory"]["items"].append(artifact_id)
        user["profile"]["artifacts_found"] += 1
    mark_discovered(user, artifact_id)

    if "artifact_failures" not in user:
        user["artifact_failures"] = {}
    if str(artifact_id) in user["artifact_failures"]:
        del user["artifact_failures"][str(artifact_id)]

    user["_words_done"] = True
    advance_daily_quest(user, "words")
    advance_daily_quest(user, "collect")
    advance_daily_quest(user, "play")
    new_achs = check_achievements(user)
    save_users(users)
    return jsonify({"success": True, "passed": True, "new_achievements": new_achs})


@app.route("/api/flappy-complete", methods=["POST"])
def flappy_complete():
    """Award artifact after flappy minigame completion"""
    data = request.get_json()
    artifact_id = data.get("artifact_id")
    nickname = get_session_user() or data.get("nickname")

    if not artifact_id or not nickname:
        return jsonify({"error": "Не переданы данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    on_cd, remaining = check_cooldown(user, artifact_id)
    if on_cd:
        return jsonify({"error": "Артефакт на кулдауне.", "remaining_time": remaining}), 400

    data_json = load_data()
    artifact = next((a for a in data_json["artifacts"] if a["id"] == artifact_id), None)
    if not artifact:
        return jsonify({"error": "Артефакт не найден."}), 404

    if artifact_id not in user["inventory"]["items"]:
        user["inventory"]["items"].append(artifact_id)
        user["profile"]["artifacts_found"] += 1
    mark_discovered(user, artifact_id)

    if "artifact_failures" not in user:
        user["artifact_failures"] = {}
    if str(artifact_id) in user["artifact_failures"]:
        del user["artifact_failures"][str(artifact_id)]

    user["_flappy_done"] = True
    advance_daily_quest(user, "flappy")
    advance_daily_quest(user, "collect")
    advance_daily_quest(user, "play")
    new_achs = check_achievements(user)
    save_users(users)
    return jsonify({"success": True, "passed": True, "new_achievements": new_achs})


@app.route("/api/piano-complete", methods=["POST"])
def piano_complete():
    """Award artifact after piano minigame completion"""
    payload = request.get_json(silent=True) or {}
    artifact_id = payload.get("artifact_id")
    nickname = get_session_user() or payload.get("nickname")

    if not artifact_id or not nickname:
        return jsonify({"error": "Не переданы данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    on_cd, remaining = check_cooldown(user, artifact_id)
    if on_cd:
        return jsonify({"error": "Артефакт на кулдауне.", "remaining_time": remaining}), 400

    data_json = load_data()
    artifact = next((a for a in data_json["artifacts"] if a["id"] == artifact_id), None)
    if not artifact:
        return jsonify({"error": "Артефакт не найден."}), 404

    if artifact_id not in user["inventory"]["items"]:
        user["inventory"]["items"].append(artifact_id)
        user["profile"]["artifacts_found"] += 1
    mark_discovered(user, artifact_id)

    if "artifact_failures" not in user:
        user["artifact_failures"] = {}
    if str(artifact_id) in user["artifact_failures"]:
        del user["artifact_failures"][str(artifact_id)]

    user["_piano_done"] = True
    advance_daily_quest(user, "piano")
    advance_daily_quest(user, "collect")
    advance_daily_quest(user, "play")
    new_achs = check_achievements(user)
    save_users(users)
    return jsonify({"success": True, "passed": True, "new_achievements": new_achs})


@app.route("/api/sell-artifact", methods=["POST"])
def sell_artifact():
    payload = request.get_json(silent=True) or {}
    artifact_id = payload.get("artifact_id")
    nickname = payload.get("nickname")
    if not artifact_id or not nickname:
        return jsonify({"error": "Не переданы данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    if artifact_id not in user.get("inventory", {}).get("items", []):
        return jsonify({"error": "Артефакт не в инвентаре."}), 400

    data_json = load_data()
    artifact = next((a for a in data_json["artifacts"] if a["id"] == artifact_id), None)
    if not artifact:
        return jsonify({"error": "Артефакт не найден."}), 404

    difficulty = (artifact.get("difficulty") or "").lower()
    if difficulty == "unique":
        return jsonify({"error": "Уникальные артефакты нельзя продать."}), 400

    price = ARTIFACT_PRICES.get(difficulty, 0)
    if price <= 0:
        return jsonify({"error": "Этот артефакт нельзя продать."}), 400

    user["inventory"]["items"].remove(artifact_id)
    user["profile"]["artifacts_found"] = max(0, user["profile"].get("artifacts_found", 0) - 1)
    user.setdefault("profile", {})["coins"] = user.get("profile", {}).get("coins", 0) + price
    user["_sold_count"] = user.get("_sold_count", 0) + 1
    advance_daily_quest(user, "sell")
    new_achs = check_achievements(user)
    save_users(users)
    return jsonify({"success": True, "coins": user["profile"]["coins"], "price": price, "new_achievements": new_achs})


@app.route("/api/leaderboard", methods=["GET"])
def leaderboard():
    """Return leaderboard sorted by artifacts_found. Optional ?city= filter."""
    city = request.args.get("city", "").strip()
    users = load_users()
    data_json = load_data()

    if city:
        # Find museums in this city
        city_museum_ids = {
            m["id"] for m in data_json.get("museums", [])
            if m.get("city", "").strip().lower() == city.lower()
        }
        # Find artifacts belonging to those museums
        city_artifact_ids = set()
        for a in data_json.get("artifacts", []):
            if a.get("museum_id") in city_museum_ids:
                city_artifact_ids.add(a["id"])
        # Count only city-relevant artifacts per user
        board = []
        for u in users:
            items = u.get("inventory", {}).get("items", [])
            count = sum(1 for item_id in items if item_id in city_artifact_ids)
            if count > 0:
                board.append({
                    "nickname": u["nickname"],
                    "avatar": u.get("profile", {}).get("avatar"),
                    "artifacts": count,
                    "equipped_frame": u.get("profile", {}).get("equipped_frame", ""),
                    "equipped_banner": u.get("profile", {}).get("equipped_banner", ""),
                })
    else:
        board = []
        for u in users:
            count = u.get("profile", {}).get("artifacts_found", 0)
            board.append({
                "nickname": u["nickname"],
                "avatar": u.get("profile", {}).get("avatar"),
                "artifacts": count,
                "equipped_frame": u.get("profile", {}).get("equipped_frame", ""),
                "equipped_banner": u.get("profile", {}).get("equipped_banner", ""),
            })

    board.sort(key=lambda x: x["artifacts"], reverse=True)

    # Add rank
    for i, entry in enumerate(board):
        entry["rank"] = i + 1

    return jsonify(board)


# ─── SHOP ─────────────────────────────────────────────
SHOP_FILE = BASE_DIR / "shop.json"

AVAILABLE_FRAMES = [
    {"id": "frame_pharaoh", "name": "Фараон", "price": 300, "image": "source/frames/frame_pharaoh.svg"},
    {"id": "frame_roman", "name": "Римская империя", "price": 300, "image": "source/frames/frame_roman.svg"},
    {"id": "frame_viking", "name": "Викинг", "price": 300, "image": "source/frames/frame_viking.svg"},
    {"id": "frame_greek", "name": "Древняя Греция", "price": 300, "image": "source/frames/frame_greek.svg"},
    {"id": "frame_aztec", "name": "Ацтеки", "price": 300, "image": "source/frames/frame_aztec.svg"},
]


def get_all_frames():
    """Return AVAILABLE_FRAMES + custom frames from shop.json."""
    shop = load_shop()
    custom = shop.get("frames", [])
    merged = {f["id"]: f for f in AVAILABLE_FRAMES}
    for f in custom:
        merged[f["id"]] = f
    return list(merged.values())


def load_shop():
    if SHOP_FILE.exists():
        with open(SHOP_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"banners": [], "frames": [], "stock_banners": [], "stock_frames": []}


def save_shop(data):
    with open(SHOP_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


@app.route("/api/shop", methods=["GET"])
def get_shop():
    shop = load_shop()
    return jsonify(shop)


@app.route("/api/shop/buy", methods=["POST"])
def shop_buy():
    body = request.get_json()
    item_id = body.get("item_id")
    item_type = body.get("item_type")  # "banner" or "frame"
    nickname = body.get("nickname")
    if not item_id or not item_type or not nickname:
        return jsonify({"error": "Неверные данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    shop = load_shop()
    stock_key = "stock_banners" if item_type == "banner" else "stock_frames"
    item = next((i for i in shop.get(stock_key, []) if i["id"] == item_id), None)
    if not item:
        return jsonify({"error": "Товар не найден в магазине."}), 404

    price = item.get("price", 0)
    coins = user.get("profile", {}).get("coins", 0)
    if coins < price:
        return jsonify({"error": "Недостаточно монет."}), 400

    inv = user.setdefault("inventory", {})
    owned_key = "banners" if item_type == "banner" else "frames"
    owned = inv.setdefault(owned_key, [])
    if item_id in owned:
        return jsonify({"error": "Уже куплено."}), 400

    user["profile"]["coins"] = coins - price
    owned.append(item_id)
    new_achs = check_achievements(user)
    save_users(users)
    return jsonify({"success": True, "coins": user["profile"]["coins"], "new_achievements": new_achs})


@app.route("/api/shop/equip", methods=["POST"])
def shop_equip():
    body = request.get_json()
    item_id = body.get("item_id")  # "" to unequip
    item_type = body.get("item_type")  # "banner" or "frame"
    nickname = body.get("nickname")
    if item_type not in ("banner", "frame") or not nickname:
        return jsonify({"error": "Неверные данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    equip_key = "equipped_banner" if item_type == "banner" else "equipped_frame"
    user["profile"][equip_key] = item_id or ""
    save_users(users)
    return jsonify({"success": True})


@app.route("/api/admin/shop/stock", methods=["POST"])
def admin_set_shop_stock():
    body = request.get_json()
    shop = load_shop()
    if "stock_banners" in body:
        shop["stock_banners"] = body["stock_banners"]
    if "stock_frames" in body:
        shop["stock_frames"] = body["stock_frames"]
    save_shop(shop)
    return jsonify({"success": True})


@app.route("/api/admin/shop/randomize", methods=["POST"])
def admin_randomize_shop():
    shop = load_shop()
    all_banners = shop.get("banners", [])
    all_frames = get_all_frames()
    shop["stock_banners"] = random.sample(all_banners, min(3, len(all_banners)))
    shop["stock_frames"] = random.sample(all_frames, min(3, len(all_frames)))
    save_shop(shop)
    return jsonify({"success": True, "shop": shop})


@app.route("/api/admin/shop/banners", methods=["GET"])
def admin_get_banners():
    shop = load_shop()
    return jsonify(shop.get("banners", []))


@app.route("/api/admin/shop/banners", methods=["POST"])
def admin_upload_banner():
    name = request.form.get("name", "Баннер")
    price = int(request.form.get("price", 200))
    file = request.files.get("image")
    if not file or not file.filename:
        return jsonify({"error": "Нет файла."}), 400

    ext = Path(secure_filename(file.filename)).suffix.lower()
    if ext not in (".jpg", ".jpeg", ".png", ".gif", ".webp"):
        return jsonify({"error": "Неподдерживаемый формат."}), 400

    banner_dir = BASE_DIR / "static" / "source" / "banners"
    banner_dir.mkdir(parents=True, exist_ok=True)
    bid = f"banner_{int(datetime.now().timestamp())}"
    fname = f"{bid}{ext}"
    file.save(banner_dir / fname)

    shop = load_shop()
    banner = {"id": bid, "name": name, "price": price, "image": f"source/banners/{fname}"}
    shop.setdefault("banners", []).append(banner)
    save_shop(shop)
    return jsonify({"success": True, "banner": banner})


@app.route("/api/admin/shop/banners/<banner_id>", methods=["DELETE"])
def admin_delete_banner(banner_id):
    shop = load_shop()
    banners = shop.get("banners", [])
    banner = next((b for b in banners if b["id"] == banner_id), None)
    if not banner:
        return jsonify({"error": "Баннер не найден."}), 404
    # Remove file
    img_path = BASE_DIR / "static" / banner["image"]
    if img_path.exists():
        img_path.unlink()
    shop["banners"] = [b for b in banners if b["id"] != banner_id]
    # Also remove from stock
    shop["stock_banners"] = [b for b in shop.get("stock_banners", []) if b["id"] != banner_id]
    save_shop(shop)
    return jsonify({"success": True})


@app.route("/api/admin/shop/frames", methods=["GET"])
def admin_get_frames():
    return jsonify(get_all_frames())


@app.route("/api/admin/shop/frames", methods=["POST"])
def admin_add_frame():
    name = request.form.get("name", "Рамка")
    price = int(request.form.get("price", 300))
    file = request.files.get("image")
    if not file or not file.filename:
        return jsonify({"error": "Нет файла."}), 400

    ext = Path(secure_filename(file.filename)).suffix.lower()
    if ext not in (".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp"):
        return jsonify({"error": "Неподдерживаемый формат."}), 400

    frame_dir = BASE_DIR / "static" / "source" / "frames"
    frame_dir.mkdir(parents=True, exist_ok=True)
    fid = f"frame_{int(datetime.now().timestamp())}"
    fname = f"{fid}{ext}"
    file.save(frame_dir / fname)

    shop = load_shop()
    frame = {"id": fid, "name": name, "price": price, "image": f"source/frames/{fname}"}
    shop.setdefault("frames", []).append(frame)
    save_shop(shop)
    return jsonify({"success": True, "frame": frame})


@app.route("/api/admin/shop/frames/<frame_id>", methods=["PUT"])
def admin_edit_frame(frame_id):
    body = request.get_json()
    # Check built-in frames
    for f in AVAILABLE_FRAMES:
        if f["id"] == frame_id:
            if "name" in body:
                f["name"] = body["name"]
            if "price" in body:
                f["price"] = int(body["price"])
            return jsonify({"success": True})
    # Check custom frames
    shop = load_shop()
    for f in shop.get("frames", []):
        if f["id"] == frame_id:
            if "name" in body:
                f["name"] = body["name"]
            if "price" in body:
                f["price"] = int(body["price"])
            save_shop(shop)
            return jsonify({"success": True})
    return jsonify({"error": "Рамка не найдена."}), 404


@app.route("/api/admin/shop/frames/<frame_id>", methods=["DELETE"])
def admin_delete_frame(frame_id):
    # Don't delete built-in frames
    if any(f["id"] == frame_id for f in AVAILABLE_FRAMES):
        return jsonify({"error": "Нельзя удалить встроенную рамку."}), 400
    shop = load_shop()
    frames = shop.get("frames", [])
    frame = next((f for f in frames if f["id"] == frame_id), None)
    if not frame:
        return jsonify({"error": "Рамка не найдена."}), 404
    img_path = BASE_DIR / "static" / frame["image"]
    if img_path.exists():
        img_path.unlink()
    shop["frames"] = [f for f in frames if f["id"] != frame_id]
    shop["stock_frames"] = [f for f in shop.get("stock_frames", []) if f["id"] != frame_id]
    save_shop(shop)
    return jsonify({"success": True})


# ─── ACHIEVEMENTS ──────────────────────────────────────
ACHIEVEMENTS = [
    {"id": "first_artifact", "name": "Первый артефакт", "desc": "Найдите свой первый артефакт", "icon": "🏺"},
    {"id": "collector_5", "name": "Начинающий коллекционер", "desc": "Соберите 5 артефактов", "icon": "📦"},
    {"id": "collector_15", "name": "Опытный коллекционер", "desc": "Соберите 15 артефактов", "icon": "🗄️"},
    {"id": "rich_1000", "name": "Нувориш", "desc": "Накопите 1000 монет", "icon": "💰"},
    {"id": "trader", "name": "Торговец", "desc": "Продайте артефакт", "icon": "🤝"},
    {"id": "quiz_master", "name": "Мастер квизов", "desc": "Пройдите квиз без единой ошибки", "icon": "🧠"},
    {"id": "flappy_hero", "name": "Герой полёта", "desc": "Пройдите Flappy-мини-игру", "icon": "🐦"},
    {"id": "piano_star", "name": "Пианист", "desc": "Пройдите Piano-мини-игру", "icon": "🎹"},
    {"id": "words_sage", "name": "Мудрец слов", "desc": "Пройдите мини-игру «Слова»", "icon": "📝"},
    {"id": "museum_3", "name": "Путешественник", "desc": "Посетите 3 разных музея", "icon": "🗺️"},
    {"id": "shopaholic", "name": "Шопоголик", "desc": "Купите предмет в магазине", "icon": "🛒"},
    {"id": "full_collection", "name": "Полная коллекция", "desc": "Соберите полную коллекцию артефактов", "icon": "⭐"},
]


def check_achievements(user):
    """Check and award achievements. Returns list of newly earned achievement IDs."""
    inv = user.setdefault("inventory", {"skins": [], "items": [], "achievements": []})
    earned = set(inv.get("achievements", []))
    new_achievements = []
    items = inv.get("items", [])
    profile = user.get("profile", {})
    coins = profile.get("coins", 0)

    def _grant(aid):
        if aid not in earned:
            earned.add(aid)
            new_achievements.append(aid)

    if len(items) >= 1:
        _grant("first_artifact")
    if len(items) >= 5:
        _grant("collector_5")
    if len(items) >= 15:
        _grant("collector_15")
    if coins >= 1000:
        _grant("rich_1000")
    if user.get("_sold_count", 0) >= 1:
        _grant("trader")
    if user.get("_quiz_perfect", False):
        _grant("quiz_master")
    if user.get("_flappy_done", False):
        _grant("flappy_hero")
    if user.get("_piano_done", False):
        _grant("piano_star")
    if user.get("_words_done", False):
        _grant("words_sage")
    # Count distinct museums
    data_json = load_data()
    artifacts_map = {a["id"]: a for a in data_json.get("artifacts", [])}
    museum_ids = set()
    for aid in items:
        art = artifacts_map.get(aid)
        if art:
            museum_ids.add(art.get("museum_id"))
    if len(museum_ids) >= 3:
        _grant("museum_3")
    if inv.get("banners") or inv.get("frames"):
        _grant("shopaholic")
    # Full collection check
    collections = load_collections()
    for col in collections:
        col_artifacts = set(col.get("artifact_ids", []))
        if col_artifacts and col_artifacts.issubset(set(items)):
            _grant("full_collection")
            break

    if new_achievements:
        inv["achievements"] = list(earned)
    return new_achievements


@app.route("/api/achievements", methods=["GET"])
def get_achievements():
    """Return all achievements + which ones the user has earned."""
    nickname = request.args.get("nickname", "").strip()
    if not nickname:
        return jsonify({"error": "Не передан никнейм."}), 400
    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404
    earned = set(user.get("inventory", {}).get("achievements", []))
    result = []
    for a in ACHIEVEMENTS:
        result.append({**a, "earned": a["id"] in earned})
    return jsonify(result)


# ─── COLLECTIONS ───────────────────────────────────────
COLLECTIONS_PATH = BASE_DIR / "collections.json"


def load_collections():
    if COLLECTIONS_PATH.exists():
        with open(COLLECTIONS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def save_collections(cols):
    with open(COLLECTIONS_PATH, "w", encoding="utf-8") as f:
        json.dump(cols, f, ensure_ascii=False, indent=2)


@app.route("/api/collections", methods=["GET"])
def get_collections():
    """Return all collections with progress for a user."""
    nickname = request.args.get("nickname", "").strip()
    collections = load_collections()
    data_json = load_data()
    artifacts_map = {a["id"]: a for a in data_json.get("artifacts", [])}

    user_items = set()
    if nickname:
        users = load_users()
        user = next((u for u in users if u["nickname"] == nickname), None)
        if user:
            user_items = set(user.get("inventory", {}).get("items", []))

    result = []
    for col in collections:
        art_ids = col.get("artifact_ids", [])
        arts = []
        for aid in art_ids:
            a = artifacts_map.get(aid)
            if a:
                arts.append({
                    "id": a["id"],
                    "name": a.get("name", ""),
                    "image": a.get("image", ""),
                    "owned": a["id"] in user_items,
                })
        result.append({
            "id": col.get("id"),
            "name": col.get("name", ""),
            "reward_type": col.get("reward_type", ""),
            "reward_id": col.get("reward_id", ""),
            "artifacts": arts,
            "total": len(art_ids),
            "collected": sum(1 for aid in art_ids if aid in user_items),
        })
    return jsonify(result)


@app.route("/api/collections/claim", methods=["POST"])
def claim_collection_reward():
    """Grant collection reward if fully completed."""
    payload = request.get_json(silent=True) or {}
    collection_id = payload.get("collection_id")
    nickname = payload.get("nickname", "").strip()
    if not collection_id or not nickname:
        return jsonify({"error": "Не переданы данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    collections = load_collections()
    col = next((c for c in collections if c.get("id") == collection_id), None)
    if not col:
        return jsonify({"error": "Коллекция не найдена."}), 404

    user_items = set(user.get("inventory", {}).get("items", []))
    col_artifacts = set(col.get("artifact_ids", []))
    if not col_artifacts.issubset(user_items):
        return jsonify({"error": "Коллекция не собрана полностью."}), 400

    claimed = set(user.get("_claimed_collections", []))
    if collection_id in claimed:
        return jsonify({"error": "Награда уже получена."}), 400

    # Grant reward
    inv = user.setdefault("inventory", {})
    reward_type = col.get("reward_type", "")
    reward_id = col.get("reward_id", "")
    if reward_type == "banner" and reward_id:
        banners = inv.setdefault("banners", [])
        if reward_id not in banners:
            banners.append(reward_id)
    elif reward_type == "frame" and reward_id:
        frames = inv.setdefault("frames", [])
        if reward_id not in frames:
            frames.append(reward_id)

    user.setdefault("_claimed_collections", []).append(collection_id)
    # Check achievements after collection claim
    new_achs = check_achievements(user)
    save_users(users)
    return jsonify({"success": True, "new_achievements": new_achs})


@app.route("/api/admin/collections", methods=["GET"])
def admin_get_collections():
    return jsonify(load_collections())


@app.route("/api/admin/collections", methods=["POST"])
def admin_create_collection():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name", "")).strip()
    artifact_ids = payload.get("artifact_ids", [])
    reward_type = str(payload.get("reward_type", "")).strip()
    reward_id = str(payload.get("reward_id", "")).strip()

    if not name:
        return jsonify({"error": "Введите название коллекции."}), 400
    if not artifact_ids or not isinstance(artifact_ids, list):
        return jsonify({"error": "Выберите артефакты."}), 400

    collections = load_collections()
    col_id = max((c.get("id", 0) for c in collections), default=0) + 1
    col = {
        "id": col_id,
        "name": name,
        "artifact_ids": [int(a) for a in artifact_ids],
        "reward_type": reward_type,
        "reward_id": reward_id,
    }
    collections.append(col)
    save_collections(collections)
    return jsonify({"success": True, "collection": col})


@app.route("/api/admin/collections/<int:col_id>", methods=["PUT"])
def admin_update_collection(col_id):
    payload = request.get_json(silent=True) or {}
    collections = load_collections()
    col = next((c for c in collections if c.get("id") == col_id), None)
    if not col:
        return jsonify({"error": "Коллекция не найдена."}), 404
    if "name" in payload:
        col["name"] = str(payload["name"]).strip()
    if "artifact_ids" in payload:
        col["artifact_ids"] = [int(a) for a in payload["artifact_ids"]]
    if "reward_type" in payload:
        col["reward_type"] = str(payload["reward_type"]).strip()
    if "reward_id" in payload:
        col["reward_id"] = str(payload["reward_id"]).strip()
    save_collections(collections)
    return jsonify({"success": True, "collection": col})


@app.route("/api/admin/collections/<int:col_id>", methods=["DELETE"])
def admin_delete_collection(col_id):
    collections = load_collections()
    if not any(c.get("id") == col_id for c in collections):
        return jsonify({"error": "Коллекция не найдена."}), 404
    collections = [c for c in collections if c.get("id") != col_id]
    save_collections(collections)
    return jsonify({"success": True})


# ─── DAILY QUESTS ──────────────────────────────────────
DAILY_QUEST_TEMPLATES = [
    {"id": "collect_2", "name": "Охотник", "desc": "Соберите 2 артефакта сегодня", "icon": "🏺", "target": 2, "type": "collect", "reward": 50},
    {"id": "quiz_perfect", "name": "Отличник", "desc": "Пройдите квиз без ошибок", "icon": "🧠", "target": 1, "type": "quiz_perfect", "reward": 75},
    {"id": "play_3", "name": "Игроман", "desc": "Сыграйте в 3 мини-игры", "icon": "🎮", "target": 3, "type": "play", "reward": 60},
    {"id": "sell_1", "name": "Делец", "desc": "Продайте артефакт", "icon": "🤝", "target": 1, "type": "sell", "reward": 40},
    {"id": "collect_3", "name": "Коллекционер дня", "desc": "Соберите 3 артефакта", "icon": "📦", "target": 3, "type": "collect", "reward": 100},
    {"id": "piano_play", "name": "Музыкант", "desc": "Пройдите Piano Tiles", "icon": "🎹", "target": 1, "type": "piano", "reward": 60},
    {"id": "flappy_play", "name": "Пилот", "desc": "Пройдите Flappy Bird", "icon": "🐦", "target": 1, "type": "flappy", "reward": 60},
    {"id": "words_play", "name": "Грамотей", "desc": "Пройдите мини-игру «Слова»", "icon": "📝", "target": 1, "type": "words", "reward": 60},
]


def get_today_str():
    return datetime.now().strftime("%Y-%m-%d")


def get_user_daily_quests(user):
    """Return 3 daily quests for user, regenerating if date changed."""
    daily = user.get("daily_quests", {})
    today = get_today_str()
    if daily.get("date") != today:
        # Pick 3 random quests for today
        chosen = random.sample(DAILY_QUEST_TEMPLATES, min(3, len(DAILY_QUEST_TEMPLATES)))
        daily = {
            "date": today,
            "quests": [{"id": q["id"], "progress": 0, "claimed": False} for q in chosen],
        }
        user["daily_quests"] = daily
    return daily


@app.route("/api/daily-quests", methods=["GET"])
def get_daily_quests():
    nickname = get_session_user() or request.args.get("nickname", "").strip()
    if not nickname:
        return jsonify({"error": "Не передан никнейм."}), 400
    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    daily = get_user_daily_quests(user)
    save_users(users)

    # Build response with full quest info
    result = []
    for dq in daily["quests"]:
        template = next((t for t in DAILY_QUEST_TEMPLATES if t["id"] == dq["id"]), None)
        if not template:
            continue
        result.append({
            **template,
            "progress": dq["progress"],
            "claimed": dq["claimed"],
        })
    return jsonify({"date": daily["date"], "quests": result})


@app.route("/api/daily-quests/claim", methods=["POST"])
def claim_daily_quest():
    payload = request.get_json(silent=True) or {}
    quest_id = payload.get("quest_id")
    nickname = get_session_user() or payload.get("nickname", "").strip()
    if not nickname or not quest_id:
        return jsonify({"error": "Не переданы данные."}), 400

    users = load_users()
    user = next((u for u in users if u["nickname"] == nickname), None)
    if not user:
        return jsonify({"error": "Пользователь не найден."}), 404

    daily = get_user_daily_quests(user)
    dq = next((q for q in daily["quests"] if q["id"] == quest_id), None)
    if not dq:
        return jsonify({"error": "Задание не найдено."}), 404

    template = next((t for t in DAILY_QUEST_TEMPLATES if t["id"] == quest_id), None)
    if not template:
        return jsonify({"error": "Шаблон задания не найден."}), 404

    if dq["claimed"]:
        return jsonify({"error": "Награда уже получена."}), 400
    if dq["progress"] < template["target"]:
        return jsonify({"error": "Задание не завершено."}), 400

    dq["claimed"] = True
    reward = template["reward"]
    user.setdefault("profile", {})["coins"] = user.get("profile", {}).get("coins", 0) + reward
    save_users(users)
    return jsonify({"success": True, "reward": reward, "coins": user["profile"]["coins"]})


def advance_daily_quest(user, quest_type):
    """Increment progress for matching daily quest type."""
    daily = user.get("daily_quests", {})
    if daily.get("date") != get_today_str():
        return
    for dq in daily.get("quests", []):
        template = next((t for t in DAILY_QUEST_TEMPLATES if t["id"] == dq["id"]), None)
        if template and template["type"] == quest_type and not dq["claimed"]:
            dq["progress"] = min(dq["progress"] + 1, template["target"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)