import os
import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from dotenv import load_dotenv
from functools import wraps
from bs4 import BeautifulSoup
import datetime
import random

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
CORS(app)
jwt = JWTManager(app)

# MongoDB setup
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client.meal_planner_db

# Ensure collections exist
if 'users' not in db.list_collection_names():
    db.create_collection('users')

# Cache object
daily_recipe_cache = {
    "date": None,
    "recipes": []
}

def get_cached_daily_spoonacular_recipes():
    global daily_recipe_cache
    today = datetime.datetime.utcnow().strftime('%Y-%m-%d')

    if daily_recipe_cache["date"] == today and daily_recipe_cache["recipes"]:
        return daily_recipe_cache["recipes"]

    api_key = os.getenv("SPOONACULAR_API_KEY")
    seed = int(datetime.datetime.utcnow().strftime('%Y%m%d'))
    random.seed(seed)
    offset = random.randint(0, 100)

    response = requests.get(
        "https://api.spoonacular.com/recipes/complexSearch",
        params={
            "apiKey": api_key,
            "number": 5,
            "offset": offset,
            "addRecipeInformation": True,
            "sort": "random"
        }
    )

    if response.status_code == 200:
        recipes = response.json().get("results", [])
        daily_recipe_cache["date"] = today
        daily_recipe_cache["recipes"] = recipes
        return recipes
    else:
        return []

@app.route('/')
def show_home():
    username = session.get('username')
    if not username:
        flash("You must be logged in to view the home page", "error")
        return redirect(url_for('show_login'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('show_login'))

    grocery_list = user.get('grocery_list', [])
    favorites = user.get('favorites', [])
    monthly_budget = user.get('monthly_budget', "")

    recommended = get_cached_daily_spoonacular_recipes()

    return render_template('home.html',
                           grocery_list=grocery_list,
                           favorites=favorites,
                           recommended=recommended,
                           monthly_budget=monthly_budget,
                           username=username)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('access_token', None)
    flash("Logged out successfully", "success")
    return redirect(url_for('show_login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    location = request.form.get('location')
    diet = request.form.get('diet')
    allergies = request.form.get('allergies')
    monthley_budget = request.form.get('monthley_budget')

    if not username or not email or not password or not confirm_password:
        flash("All fields are required", "error")
        return redirect(url_for('register'))

    if password != confirm_password:
        flash("Passwords do not match", "error")
        return redirect(url_for('register'))

    if db.users.find_one({"username": username}):
        flash("Username already exists", "error")
        return redirect(url_for('register'))

    if db.users.find_one({"email": email}):
        flash("Email already exists", "error")
        return redirect(url_for('register'))

    if diet == "" or allergies == "":
        diet = []
        allergies = []

    hashed_password = generate_password_hash(password)
    db.users.insert_one({
        "username": username,
        "email": email,
        "password": hashed_password,
        "location": location,
        "diet": diet,
        "allergies": allergies,
        "monthly_budget": monthley_budget,
    })

    flash("User registered successfully", "success")
    return redirect(url_for('show_login'))

@app.route('/login', methods=['GET', 'POST'])
def show_login():
    if request.method == 'GET':
        return render_template('login.html')

    username = request.form.get('username')
    password = request.form.get('password')

    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if username == admin_username and password == admin_password:
        return redirect(url_for('show_admin'))

    if not username or not password:
        flash("Username and password are required", "error")
        return redirect(url_for('show_login'))

    user = db.users.find_one({"username": username})
    if not user or not check_password_hash(user['password'], password):
        flash("Invalid username or password", "error")
        return redirect(url_for('show_login'))

    access_token = create_access_token(identity=username)
    session['username'] = username
    session['access_token'] = access_token
    flash("Login successful", "success")
    return redirect(url_for('show_home'))

@app.route('/admin')
def show_admin():
    return render_template('admin.html')

@app.route('/grocery-list')
def show_grocery_list():
    username = session.get('username')
    if not username:
        flash("You must be logged in", "error")
        return redirect(url_for('show_login'))

    user = db.users.find_one({"username": username})
    grocery_list = user.get('grocery_list', [])
    return render_template('grocery_list.html', grocery_list=grocery_list)

@app.route('/favorites')
def show_favorites():
    username = session.get('username')
    if not username:
        flash("You must be logged in", "error")
        return redirect(url_for('show_login'))

    user = db.users.find_one({"username": username})
    favorites = user.get('favorites', [])
    return render_template('favorites.html', favorites=favorites)

@app.route('/recipes')
def show_recipes():
    return render_template('recipes.html')

@app.route('/money-spent', methods=['GET', 'POST'])
def money_spent():
    username = session.get('username')
    if not username:
        flash("You must be logged in", "error")
        return redirect(url_for('show_login'))

    now = datetime.datetime.now()
    month_key = f"{now.year}-{now.month:02d}"

    record = db.spending.find_one({"username": username})
    if not record:
        record = {"username": username, "spending": {}, "archive": {}}
        db.spending.insert_one(record)

    if request.method == 'POST':
        if 'reset' in request.form:
            current_values = record.get("spending", {}).get(month_key, [])
            archive_values = [v["amount"] if isinstance(v, dict) else v for v in current_values]
            db.spending.update_one(
                {"username": username},
                {
                    "$push": {f"archive.{month_key}": {"$each": archive_values}},
                    "$set": {f"spending.{month_key}": []}
                }
            )
            flash("Spending archived", "success")
        else:
            try:
                amount = float(request.form.get('amount', 0))
                if amount > 0:
                    entry = {"amount": amount, "date": now.strftime("%Y-%m-%d")}
                    db.spending.update_one(
                        {"username": username},
                        {"$push": {f"spending.{month_key}": entry}}
                    )
                    flash(f"Added ${amount:.2f}", "success")
                else:
                    flash("Please enter a positive amount.", "error")
            except ValueError:
                flash("Invalid amount.", "error")
        return redirect(url_for('money_spent'))

    record = db.spending.find_one({"username": username})
    values = record.get("spending", {}).get(month_key, [])
    values = [v if isinstance(v, dict) else {"amount": v, "date": ""} for v in values]
    total = sum(v["amount"] for v in values)
    return render_template('money_spent.html', values=values, total=total, month=now.strftime('%B'), year=now.year)

@app.route('/search-recipes')
def search_recipes():
    ingredient = request.args.get('ingredient')
    if not ingredient:
        flash("Ingredient is required", "error")
        return redirect(url_for('show_recipes'))

    api_key = os.getenv("SPOONACULAR_API_KEY")
    url = f"https://api.spoonacular.com/recipes/complexSearch?query={ingredient}&apiKey={api_key}&addRecipeInformation=true&number=9"
    response = requests.get(url)
    if response.status_code == 200:
        recipes = response.json().get('results', [])
        username = session.get('username')
        user = db.users.find_one({"username": username})
        allergies = user.get('allergies', []) if user else []
        for recipe in recipes:
            recipe['has_allergy'] = any(allergy.lower() in str(recipe).lower() for allergy in allergies)
        return render_template('recipes.html', recipes=recipes, ingredient=ingredient)
    else:
        flash("Failed to fetch recipes", "error")
        return redirect(url_for('show_recipes'))

@app.route('/search-user')
def search_user():
    username = request.args.get('user')
    if not username:
        flash("Please enter a username", "error")
        return redirect(url_for('show_admin'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('show_admin'))

    spending_record = db.spending.find_one({"username": username})
    monthly_spending = {}
    if spending_record:
        for month, values in spending_record.get("spending", {}).items():
            monthly_spending[month] = sum(values)
        for month, values in spending_record.get("archive", {}).items():
            monthly_spending[month] = monthly_spending.get(month, 0) + sum(values)

    return render_template('admin.html', user=user, monthly_spending=monthly_spending or None)

@app.route("/api/get-key")
def get_key():
    return jsonify({"apiKey": os.getenv("GML_API_KEY")})

@app.route('/scrape-ingredients', methods=['POST'])
def scrape_ingredients():
    username = session.get('username')
    if not username:
        return jsonify({"msg": "You must be logged in"}), 401

    user = db.users.find_one({"username": username})
    if not user:
        return jsonify({"msg": "User not found"}), 404

    url = request.json.get('url')
    if not url:
        return jsonify({"msg": "URL is required"}), 400

    response = requests.get(url)
    if response.status_code != 200:
        return jsonify({"msg": "Failed to fetch recipe page"}), 500

    soup = BeautifulSoup(response.content, 'html.parser')
    ingredients = soup.find_all(attrs={"itemprop": "ingredients"})
    for i in ingredients:
        if i.text.strip().lower()[-1] != ":":
            db.users.update_one({"username": username}, {"$push": {"grocery_list": i.text.strip().lower()}})

    if not ingredients:
        return jsonify({"msg": "No ingredients found"}), 404

    return jsonify({"msg": "Ingredients added to grocery list"}), 200

if __name__ == "__main__":
    app.run(debug=True)
