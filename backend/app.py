from flask import Flask, request, jsonify, send_file
from flask_pymongo import PyMongo
from flask_cors import CORS
from passlib.hash import bcrypt
import os
from dotenv import load_dotenv
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# MongoDB Atlas connection
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
mongo = PyMongo(app)

# Create admin if not exists
if not mongo.db.admins.find_one({"username": "Sreyashee"}):
    hashed_pw = bcrypt.hash("Sreyashee")
    mongo.db.admins.insert_one({"username": "Sreyashee", "password": hashed_pw})
    print("✅ Admin user created: Sreyashee / Sreyashee")

# ---------------- LOGIN ----------------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    admin = mongo.db.admins.find_one({"username": username})
    if admin and bcrypt.verify(password, admin["password"]):
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

# ---------------- GENERATE CERTIFICATE ----------------
@app.route("/api/generate", methods=["POST"])
def generate_certificate():
    name = request.form.get("name")
    course = request.form.get("course")
    date1 = request.form.get("date1")
    date2 = request.form.get("date2")

    # Files
    logo_file = request.files.get("logo")
    sig_director_file = request.files.get("sig_director")
    sig_ceo_file = request.files.get("sig_ceo")

    # Load template
    cert = Image.open("template/template.png").convert("RGBA")
    draw = ImageDraw.Draw(cert)

    font_name = ImageFont.truetype("arial.ttf", 60)
    font_details = ImageFont.truetype("arial.ttf", 30)
    font_date = ImageFont.truetype("arial.ttf", 20)

    draw.text((578, 365), name, font=font_name, fill=(68, 64, 64), anchor="mm")
    draw.text((561, 473), course, font=font_details, fill=(64, 64, 64), anchor="mm")
    draw.text((420, 533), date1, font=font_date, fill=(64, 64, 64), anchor="mm")
    draw.text((620, 533), date2, font=font_date, fill=(64, 64, 64), anchor="mm")

    # Add images if uploaded
    if logo_file:
        logo = Image.open(logo_file).convert("RGBA").resize((120, 120))
        cert.paste(logo, (480, 575), logo)

    if sig_director_file:
        sig_director = Image.open(sig_director_file).convert("RGBA").resize((120, 80))
        cert.paste(sig_director, (270, 575), sig_director)

    if sig_ceo_file:
        sig_ceo = Image.open(sig_ceo_file).convert("RGBA").resize((120, 80))
        cert.paste(sig_ceo, (700, 575), sig_ceo)

    # Save to BytesIO
    output = BytesIO()
    cert.convert("RGB").save(output, "PDF")
    output.seek(0)

    return send_file(output, as_attachment=True, download_name=f"{name}_certificate.pdf", mimetype="application/pdf")

if __name__ == "__main__":
    app.run(debug=True)
