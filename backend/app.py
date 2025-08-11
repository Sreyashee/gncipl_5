from flask import Flask, request, jsonify, send_file
from flask_pymongo import PyMongo
from flask_cors import CORS
from passlib.hash import bcrypt
import os
from dotenv import load_dotenv
from io import BytesIO
from PIL import Image, ImageDraw

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FRONTEND_ORIGIN = "https://gncipl-5.vercel.app"

app = Flask(__name__)

CORS(
    app,
    origins=[FRONTEND_ORIGIN],
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "OPTIONS"]
)

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
    try:
        name = request.form.get("name")
        course = request.form.get("course")
        date1 = request.form.get("date1")
        date2 = request.form.get("date2")

        # Files
        logo_file = request.files.get("logo")
        sig_director_file = request.files.get("sig_director")
        sig_ceo_file = request.files.get("sig_ceo")

        # Load template
        cert_path = os.path.join(BASE_DIR, "template", "template.png")
        cert = Image.open(cert_path).convert("RGBA")
        draw = ImageDraw.Draw(cert)

        # Draw text using default font (no font parameter)
        draw.text((578, 365), name, fill=(68, 64, 64), anchor="mm")
        draw.text((561, 473), course, fill=(64, 64, 64), anchor="mm")
        draw.text((420, 533), date1, fill=(64, 64, 64), anchor="mm")
        draw.text((620, 533), date2, fill=(64, 64, 64), anchor="mm")

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

        return send_file(
            output,
            as_attachment=True,
            download_name=f"{name}_certificate.pdf",
            mimetype="application/pdf"
        )
    except Exception as e:
        print("Error generating certificate:", e)
        return jsonify({"message": "Server error generating certificate", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)


