from flask import Flask, render_template, request, jsonify, Response
from scam_rules import analyze_content
from flask import send_from_directory

app = Flask(__name__)

# -----------------------------
# Home Route
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")
@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico')

# -----------------------------
# robots.txt (FIXED)
# -----------------------------
@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\nAllow: /\nSitemap: https://fakecut.onrender.com/sitemap.xml",
        mimetype="text/plain"
    )


# -----------------------------
# sitemap.xml (FIXED)
# -----------------------------
@app.route("/sitemap.xml")
def sitemap():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
   <url>
      <loc>https://fakecut.onrender.com/</loc>
   </url>
</urlset>"""
    return Response(xml, mimetype="application/xml")


# -----------------------------
# Analyze Route
# -----------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    url  = data.get("url", "")

    if not text.strip() and not url.strip():
        return jsonify({"error": "Please provide text or a URL."}), 400

    result = analyze_content(text=text, url=url)
    return jsonify(result)


# -----------------------------
# Feedback Route
# -----------------------------
@app.route("/feedback", methods=["POST"])
def feedback():
    data = request.get_json(silent=True) or {}
    rating = data.get("rating", "N/A")

    print(f"⭐ User rating: {rating}")  # visible in Render logs

    return jsonify({"ok": True})


# -----------------------------
# Run App (Local Only)
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)
