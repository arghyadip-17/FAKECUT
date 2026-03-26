from flask import Flask, render_template, request, jsonify
from scam_rules import analyze_content

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")
@app.route("/robots.txt")
def robots():
    return app.send_static_file("robots.txt")

@app.route("/sitemap.xml")
def sitemap():
    return app.send_static_file("sitemap.xml")

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    url  = data.get("url", "")

    if not text.strip() and not url.strip():
        return jsonify({"error": "Please provide text or a URL."}), 400

    result = analyze_content(text=text, url=url)
    return jsonify(result)


@app.route("/feedback", methods=["POST"])
def feedback():
    data   = request.get_json(silent=True) or {}
    rating = data.get("rating", "N/A")
    print(f"⭐ User rating: {rating}")   # shows in your terminal/server logs
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True)
