# 🚀 FAKECUT — Scam Detection Web App

> ⚡ Detect fake job offers, internships, scholarships, and freelance scams instantly.

🌐 **Live Demo:** [https://fakecut.onrender.com](https://fakecut.onrender.com)

---

## ✨ Overview

**FAKECUT** is a lightweight yet powerful scam detection web application that helps users identify suspicious opportunities online.

Paste any job post, internship offer, scholarship message, or freelance listing — and get an instant risk analysis with explanations.

---

## 🔥 Features

* 🧠 Rule-based scam detection engine
* 🔍 Analyze **text or URLs**
* 📊 Risk **score + verdict system**
* ⚠️ Highlights suspicious patterns
* 💡 Provides safety advice
* 🌐 Clean browser-based UI

---

## 🧪 How It Works

```text
User Input → Flask Backend → Scam Rules Engine → Risk Analysis → Response
```

### 📊 Score Interpretation

| Score Range | Verdict       |
| ----------- | ------------- |
| 0 – 30      | ✅ Likely Safe |
| 31 – 60     | ⚠️ Caution    |
| 61 – 100    | 🚨 Suspicious |

---

## 🛠️ Tech Stack

| Layer      | Technology     |
| ---------- | -------------- |
| Backend    | Flask (Python) |
| Server     | Gunicorn       |
| Frontend   | HTML, CSS, JS  |
| Deployment | Render         |

---

## 📂 Project Structure

```bash
FAKECUT/
├── app.py                 # Flask app
├── scam_rules.py          # Detection logic
├── requirements.txt
│
├── templates/
│   └── index.html         # Frontend UI
│
└── static/
    ├── style.css
    ├── script.js
    ├── images
    └── favicon files
```

---

## 🚀 API Endpoints

### 🔹 Home

```
GET /
```

Returns the web interface.

---

### 🔹 Analyze Content

```
POST /analyze
```

#### Request

```json
{
  "text": "Pay ₹500 registration fee to get job",
  "url": ""
}
```

#### Response

```json
{
  "score": 85,
  "verdict": "Suspicious",
  "reasons": ["Asks for money"],
  "advice": ["Avoid paying upfront fees"]
}
```

---

### 🔹 Feedback

```
POST /feedback
```

```json
{
  "rating": 5
}
```

---

## 🧠 Why This Project Matters

Online scams are increasing rapidly — especially fake job offers targeting students.

**FAKECUT helps users:**

* Avoid financial fraud 💸
* Detect suspicious patterns 🔍
* Make safer decisions ⚠️

---


## 👨‍💻 Author

**Arghyadip Ghosh**
---

## ⭐ Support

If you like this project:

* ⭐ Star the repo
* 🍴 Fork it
* 📢 Share it

---

## ⚠️ Disclaimer

FAKECUT is an **early warning system**, not a final authority.
Always verify sources before trusting any opportunity.

---

> 🚀 Built to fight scams and protect users online
