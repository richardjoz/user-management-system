# 🧑‍💻 User Management System (Django REST + JS Frontend)

A full-stack demo project with:
- **Backend:** Django REST Framework + JWT Authentication + SQLAlchemy
- **Frontend:** HTML, Bootstrap 5, jQuery
- **Features:**
  - Register / Login / Logout
  - Profile View & Update
  - Password Reset
  - Notes CRUD with file attachments

## ⚙️ Setup Instructions
### Create and activate a virtual environment
### 🪟 On Windows:
```bash
python -m venv myenv
myenv\Scripts\activate
```
### 🐧 On macOS / Linux:
```bash
python3 -m venv myenv
source myenv/bin/activate
```
```bash
pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
python manage.py runserver
