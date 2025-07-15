import os
import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from functools import wraps
from bs4 import BeautifulSoup
import datetime
import random

from supabase import create_client, Client

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
CORS(app)
jwt = JWTManager(app)

# Supabase setup
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

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

    user_resp = supabase.table("users").select("*").eq("username", username).execute()
    users = user_resp.data if user_resp.data else []
    if not users:
        flash("User not found", "error")
        return redirect(url_for('show_login'))
    user = users[0]
    grocery_list = user.get('grocery_list', []) or []
    favorites = user.get('favorites', []) or []
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

    user_exists = supabase.table("users").select("id").eq("username", username).execute().data
    email_exists = supabase.table("users").select("id").eq("email", email).execute().data
    if user_exists:
        flash("Username already exists", "error")
        return redirect(url_for('register'))
    if email_exists:
        flash("Email already exists", "error")
        return redirect(url_for('register'))

    if diet == "" or allergies == "":
        diet = []
        allergies = []

    hashed_password = generate_password_hash(password)
    supabase.table("users").insert({
        "username": username,
        "email": email,
        "password": hashed_password,
        "location": location,
        "diet": diet,
        "allergies": allergies,
        "monthly_budget": monthley_budget,
        "grocery_list": [],
        "favorites": []
    }).execute()

    supabase.table("spending").insert({
        "username": username,
        "spending": [],
        "archive": []
    }).execute()

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

    user_resp = supabase.table("users").select("*").eq("username", username).execute()
    users = user_resp.data if user_resp.data else []
    if not users:
        flash("User not found", "error")
        return redirect(url_for('show_login'))
    user = users[0]
    if not check_password_hash(user['password'], password):
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

    user_resp = supabase.table("users").select("grocery_list").eq("username", username).execute()
    users = user_resp.data if user_resp.data else []
    grocery_list = users[0]['grocery_list'] if users and 'grocery_list' in users[0] else []
    return render_template('grocery_list.html', grocery_list=grocery_list)

@app.route('/grocery-list/add', methods=['POST'])
def grocery_list_add():
    username = session.get('username')
    if not username:
        flash("You must be logged in", "error")
        return redirect(url_for('show_login'))

    item = request.form.get('item')
    if not item:
        flash("Item cannot be empty", "error")
        return redirect(url_for('show_grocery_list'))

    user_resp = supabase.table("users").select("grocery_list").eq("username", username).execute()
    users = user_resp.data if user_resp.data else []
    grocery_list = users[0]['grocery_list'] if users and 'grocery_list' in users[0] else []
    
    grocery_list.append(item.lower())
    supabase.table("users").update({"grocery_list": grocery_list}).eq("username", username).execute()

    flash(f"Added '{item}' to grocery list", "success")
    return redirect(url_for('show_grocery_list'))

@app.route('/grocery-list/remove', methods=['POST'])
def grocery_list_delete():
    username = session.get('username')
    if not username:
        flash("You must be logged in", "error")
        return redirect(url_for('show_login'))

    item = request.form.get('item')
    if not item:
        flash("Item cannot be empty", "error")
        return redirect(url_for('show_grocery_list'))

    user_resp = supabase.table("users").select("grocery_list").eq("username", username).execute()
    users = user_resp.data if user_resp.data else []
    grocery_list = users[0]['grocery_list'] if users and 'grocery_list' in users[0] else []

    if item.lower() in grocery_list:
        grocery_list.remove(item.lower())
        supabase.table("users").update({"grocery_list": grocery_list}).eq("username", username).execute()
        flash(f"Removed '{item}' from grocery list", "success")
    else:
        flash(f"'{item}' not found in grocery list", "error")

    return redirect(url_for('show_grocery_list'))

@app.route('/grocery-list/favorite', methods=['POST'])
def grocery_list_favorite():
    username = session.get('username')
    if not username:
        flash("You must be logged in", "error")
        return redirect(url_for('show_login'))

    item = request.form.get('item')
    if not item:
        flash("Item cannot be empty", "error")
        return redirect(url_for('show_grocery_list'))

    user_resp = supabase.table("users").select("favorites").eq("username", username).execute()
    users = user_resp.data if user_resp.data else []
    favorites = users[0]['favorites'] if users and 'favorites' in users[0] else []

    if item.lower() not in favorites:
        favorites.append(item.lower())
        supabase.table("users").update({"favorites": favorites}).eq("username", username).execute()
        flash(f"Added '{item}' to favorites", "success")
    else:
        flash(f"'{item}' is already in favorites", "error")

    return redirect(url_for('show_grocery_list'))

@app.route('/favorites')
def show_favorites():
    username = session.get('username')
    if not username:
        flash("You must be logged in", "error")
        return redirect(url_for('show_login'))

    user_resp = supabase.table("users").select("favorites").eq("username", username).execute()
    users = user_resp.data if user_resp.data else []
    favorites = users[0]['favorites'] if users and 'favorites' in users[0] else []
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

    record_resp = supabase.table("spending").select("*").eq("username", username).execute()
    record = record_resp.data if record_resp.data else None
    if not record:
        record = {"username": username, "spending": {}, "archive": {}}
        supabase.table("spending").insert(record).execute()

    if request.method == 'POST':
        if 'reset' in request.form:
            current_values = record.get("spending", {}).get(month_key, [])
            archive_values = [v["amount"] if isinstance(v, dict) else v for v in current_values]
            new_archive = record.get("archive", {})
            new_archive[month_key] = new_archive.get(month_key, []) + archive_values
            supabase.table("spending").update({
                "archive": new_archive,
                "spending": {**record.get("spending", {}), month_key: []}
            }).eq("username", username).execute()
            flash("Spending archived", "success")
        else:
            try:
                amount = float(request.form.get('amount', 0))
                if amount > 0:
                    entry = {"amount": amount, "date": now.strftime("%Y-%m-%d")}
                    spending = record.get("spending", {})
                    spending.setdefault(month_key, [])
                    spending[month_key].append(entry)
                    supabase.table("spending").update({"spending": spending}).eq("username", username).execute()
                    flash(f"Added ${amount:.2f}", "success")
                else:
                    flash("Please enter a positive amount.", "error")
            except ValueError:
                flash("Invalid amount.", "error")
        return redirect(url_for('money_spent'))

    record_resp = supabase.table("spending").select("*").eq("username", username).execute()
    record = record_resp.data if record_resp.data else {}
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
        user_resp = supabase.table("users").select("allergies").eq("username", username).execute()
        users = user_resp.data if user_resp.data else []
        allergies = users[0]['allergies'] if users and 'allergies' in users[0] else []
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

    user_resp = supabase.table("users").select("*").eq("username", username).execute()
    user = user_resp.data if user_resp.data else None
    if not user:
        flash("User not found", "error")
        return redirect(url_for('show_admin'))

    spending_resp = supabase.table("spending").select("*").eq("username", username).execute()
    spending_record = spending_resp.data if spending_resp.data else {}
    monthly_spending = {}
    if spending_record:
        for month, values in spending_record.get("spending", {}).items():
            monthly_spending[month] = sum([v["amount"] if isinstance(v, dict) else v for v in values])
        for month, values in spending_record.get("archive", {}).items():
            monthly_spending[month] = monthly_spending.get(month, 0) + sum([v if isinstance(v, (int, float)) else v.get("amount", 0) for v in values])

    return render_template('admin.html', user=user, monthly_spending=monthly_spending or None)

@app.route("/api/get-key")
def get_key():
    return jsonify({"apiKey": os.getenv("GML_API_KEY")})

@app.route('/scrape-ingredients', methods=['POST'])
def scrape_ingredients():
    username = session.get('username')
    if not username:
        return jsonify({"msg": "You must be logged in"}), 401

    user_resp = supabase.table("users").select("grocery_list").eq("username", username).execute()
    grocery_list = user_resp.data.get('grocery_list', []) if user_resp.data else []

    url = request.json.get('url')
    if not url:
        return jsonify({"msg": "URL is required"}), 400

    response = requests.get(url)
    if response.status_code != 200:
        return jsonify({"msg": "Failed to fetch recipe page"}), 500

    soup = BeautifulSoup(response.content, 'html.parser')
    ingredients = soup.find_all(attrs={"itemprop": "ingredients"})
    new_items = []
    for i in ingredients:
        item = i.text.strip().lower()
        if item[-1] != ":":
            new_items.append(item)

    grocery_list.extend(new_items)
    supabase.table("users").update({"grocery_list": grocery_list}).eq("username", username).execute()

    if not ingredients:
        return jsonify({"msg": "No ingredients found"}), 404

    return jsonify({"msg": "Ingredients added to grocery list"}), 200

if __name__ == '__main__':
    app.run(debug=True)