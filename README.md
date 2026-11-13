# NetCollab — Member 1 Module

A starter implementation of Member 1's module:
- Registration, JWT login, profile
- MetaMask wallet-address linking
- Team creation and membership management
- Team channels
- Projects, tasks and milestones

## Requirements
- Python 3.10+
- MySQL Server 8.x (your current MySQL 8.0.44 is supported by Django 5.2)
- Node.js LTS
- MetaMask browser extension (optional, for wallet linking)

## 1. Database
Create the database in MySQL:
```sql
CREATE DATABASE netcollab_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

## 2. Backend setup (Windows PowerShell)
Open a terminal in `backend`:
```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```
Edit `backend/.env` and enter your MySQL username/password and port.
Your MySQL configuration previously showed port 3307, so the example uses 3307.

Then:
```powershell
python manage.py makemigrations accounts teams projects
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```
Backend: http://127.0.0.1:8000/

## 3. Frontend setup
Open another terminal in `frontend`:
```powershell
npm install
Copy-Item .env.example .env
npm run dev
```
Frontend: http://localhost:5173/

## 4. How to use
1. Register a user.
2. Log in.
3. Create a team.
4. Add another registered user by username.
5. Create a channel.
6. Create a project, assign tasks to team members, and add milestones.
7. Optionally connect MetaMask from the dashboard.

## API overview
- POST `/api/accounts/register/`
- POST `/api/accounts/login/`
- POST `/api/accounts/token/refresh/`
- GET `/api/accounts/profile/`
- PATCH `/api/accounts/profile/`
- POST `/api/accounts/wallet/`
- GET/POST `/api/teams/`
- GET `/api/teams/<id>/`
- POST `/api/teams/<id>/members/`
- DELETE `/api/teams/<id>/members/<user_id>/`
- GET/POST `/api/teams/<id>/channels/`
- GET/POST `/api/projects/`
- GET `/api/projects/<id>/`
- GET/POST `/api/projects/<id>/tasks/`
- PATCH `/api/tasks/<id>/`
- GET/POST `/api/projects/<id>/milestones/`
- PATCH `/api/milestones/<id>/`

## Important notes
- This is the Member 1 module, not the complete four-member NetCollab application.
- Wallet linking stores the connected public wallet address. It does not sign transactions or implement smart contracts; Member 4 handles blockchain verification.
- JWT tokens are stored in browser localStorage for this lab prototype. For production, use a more secure token-storage strategy and HTTPS.
- Before integrating with teammates' modules, agree on model/API field names and ownership rules.
