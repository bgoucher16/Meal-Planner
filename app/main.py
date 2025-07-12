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
from userRoutes import user_routes
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

# Ensure the users collection exists
if 'users' not in db.list_collection_names():
    db.create_collection('users')

@app.route("/api/get-key")
def get_key():
    return jsonify({"apiKey": os.getenv("GML_API_KEY")})

@app.route('/register', methods=['POST'])
def register():
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
        return redirect(url_for('user_routes.show_register'))

    if password != confirm_password:
        flash("Passwords do not match", "error")
        return redirect(url_for('user_routes.show_register'))

    if db.users.find_one({"username": username}):
        flash("Username already exists", "error")
        return redirect(url_for('user_routes.show_register'))

    if db.users.find_one({"email": email}):
        flash("Email already exists", "error")
        return redirect(url_for('user_routes.show_register'))
    
    if diet == "" or allergies == "":
        diet = []
        allergies = []

    hashed_password = generate_password_hash(password)
    db.users.insert_one({"username": username, 
                         "email": email, 
                         "password": hashed_password, 
                         "location": location,
                         "diet": diet,
                         "allergies": allergies,
                         "monthly_budget": monthley_budget,})
    flash("User registered successfully", "success")
    return redirect(url_for('user_routes.show_login'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if username == admin_username and password == admin_password:
        return redirect(url_for('user_routes.show_admin'))

    if not username or not password:
        flash("Username and password are required", "error")
        return redirect(url_for('user_routes.show_login'))

    user = db.users.find_one({"username": username})
    if not user or not check_password_hash(user['password'], password):
        flash("Invalid username or password", "error")
        return redirect(url_for('user_routes.show_login'))

    access_token = create_access_token(identity=username)
    session['username'] = username
    session['access_token'] = access_token
    flash("Login successful", "success")
    return redirect(url_for('user_routes.show_home'))

@app.route('/grocery-list-add', methods=['POST'])
def grocery_list_add():
    username = session.get('username')
    if not username:
        flash("You must be logged in to add items to your grocery list", "error")
        return redirect(url_for('user_routes.show_login'))
    
    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('user_routes.show_login'))

    # Initialize grocery_list if it doesn't exist
    if "grocery_list" not in user:
        db.users.update_one({"username": username}, {"$set": {"grocery_list": []}})

    # Get and validate the item
    item = request.form.get('item', '').strip().lower()
    if not item:
        flash("Item is required", "error")
        return redirect(url_for('user_routes.show_grocery_list'))
    
    if item in user['grocery_list']:
        flash("Item already exists in grocery list", "error")
        return redirect(url_for('user_routes.show_grocery_list'))
    
    # Add item to the grocery list
    db.users.update_one({"username": username}, {"$push": {"grocery_list": item}})
    flash("Item added to grocery list", "success")
    return redirect(url_for('user_routes.show_grocery_list'))

#for readding favorite items to the grocery list whilst staying on the favorites page
@app.route('/grocery-list-add-favorites', methods=['POST'])
def grocery_list_add_favorites():
    username = session.get('username')
    if not username:
        flash("You must be logged in to add items to your grocery list", "error")
        return redirect(url_for('user_routes.show_login'))
    
    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('user_routes.show_login'))

    # Initialize grocery_list if it doesn't exist
    if "grocery_list" not in user:
        db.users.update_one({"username": username}, {"$set": {"grocery_list": []}})

    # Get and validate the item
    item = request.form.get('item', '').strip().lower()
    if not item:
        flash("Item is required", "error")
        return redirect(url_for('user_routes.show_favorites'))
    
    if item in user['grocery_list']:
        flash("Item already exists in grocery list", "error")
        return redirect(url_for('user_routes.show_favorites'))
    
    # Add item to the grocery list
    db.users.update_one({"username": username}, {"$push": {"grocery_list": item}})
    flash("Item added to grocery list", "success")
    return redirect(url_for('user_routes.show_favorites'))

@app.route('/grocery-list-delete', methods=['POST'])
def grocery_list_delete():
    username = session.get('username')
    if not username:
        flash("You must be logged in to delete items from your grocery list", "error")
        return redirect(url_for('user_routes.show_login'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('user_routes.show_login'))

    # Get and validate the item
    item = request.form.get('item', '').strip().lower()
    if not item:
        flash("Item is required", "error")
        return redirect(url_for('user_routes.show_grocery_list'))

    # Delete item from the grocery list
    db.users.update_one({"username": username}, {"$pull": {"grocery_list": item}})
    flash("Item deleted from grocery list", "success")
    return redirect(url_for('user_routes.show_grocery_list'))

@app.route('/grocery-list-favorite', methods=['POST'])
def grocery_list_favorite():
    username = session.get('username')
    if not username:
        flash("You must be logged in to favorite items from your grocery list", "error")
        return redirect(url_for('user_routes.show_login'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('user_routes.show_login'))

    # Get and validate the item
    item = request.form.get('item', '').strip().lower()
    if not item:
        flash("Item is required", "error")
        return redirect(url_for('user_routes.show_grocery_list'))

    # Add item to the favorites list
    if "favorites" not in user:
        db.users.update_one({"username": username}, {"$set": {"favorites": []}})

    if item in user["favorites"]:
        flash("Item already favorited", "error")
        return redirect(url_for('user_routes.show_grocery_list'))
    
    db.users.update_one({"username": username}, {"$push": {"favorites": item}})
    flash("Item favorited", "success")
    return redirect(url_for('user_routes.show_grocery_list'))

@app.route('/grocery-list-unfavorite', methods=['POST'])
def grocery_list_unfavorite():
    username = session.get('username')
    if not username:
        flash("You must be logged in to unfavorite items from your grocery list", "error")
        return redirect(url_for('user_routes.show_login'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('user_routes.show_login'))

    # Get and validate the item
    item = request.form.get('item', '').strip().lower()
    if not item:
        flash("Item is required", "error")
        return redirect(url_for('user_routes.show_grocery_list'))

    # Remove item from the favorites list
    db.users.update_one({"username": username}, {"$pull": {"favorites": item}})
    flash("Item unfavorited", "success")
    return redirect(url_for('user_routes.show_favorites'))

@app.route('/money-spent', methods=['GET', 'POST'])
def money_spent():
    username = session.get('username')
    if not username:
        flash("You must be logged in to track spending.", "error")
        return redirect(url_for('user_routes.show_login'))

    now = datetime.datetime.now()
    month_key = f"{now.year}-{now.month:02d}"

    # Find or create the user's spending doc
    record = db.spending.find_one({"username": username})
    if not record:
        record = {"username": username, "spending": {}, "archive": {}}
        db.spending.insert_one(record)

    # Ensure the month exists in both spending and archive
    if "spending" not in record:
        record["spending"] = {}
    if "archive" not in record:
        record["archive"] = {}
    if month_key not in record["spending"]:
        record["spending"][month_key] = []
    if month_key not in record["archive"]:
        record["archive"][month_key] = []

    if request.method == 'POST':
        if 'reset' in request.form:
            # Move current month's spending to archive
            record = db.spending.find_one({"username": username})  # Refresh in case of changes
            current_values = record.get("spending", {}).get(month_key, [])
            if current_values:
                # Only store the amount in archive (strip date if present)
                archive_values = [
                    v["amount"] if isinstance(v, dict) and "amount" in v else v
                    for v in current_values
                ]
                db.spending.update_one(
                    {"username": username},
                    {
                        "$push": {f"archive.{month_key}": {"$each": archive_values}},
                        "$set": {f"spending.{month_key}": []}
                    }
                )
            else:
                db.spending.update_one(
                    {"username": username},
                    {"$set": {f"spending.{month_key}": []}}
                )
            flash("Spending archived for this month. Previous data is still available to admin.", "success")
            return redirect(url_for('money_spent'))
        else:
            try:
                amount = float(request.form.get('amount', 0))
                if amount > 0:
                    # Store amount with date
                    entry = {
                        "amount": amount,
                        "date": now.strftime("%Y-%m-%d")
                    }
                    db.spending.update_one(
                        {"username": username},
                        {"$push": {f"spending.{month_key}": entry}}
                    )
                    flash(f"Added ${amount:.2f} to your spending.", "success")
                else:
                    flash("Please enter a positive amount.", "error")
            except ValueError:
                flash("Invalid amount.", "error")
            return redirect(url_for('money_spent'))

    # Fetch updated record
    record = db.spending.find_one({"username": username})
    values = record.get("spending", {}).get(month_key, [])
    # For backward compatibility: if any value is a float/int, convert to dict with no date
    values = [
        v if isinstance(v, dict) else {"amount": v, "date": ""}
        for v in values
    ]
    total = sum(v["amount"] for v in values)
    return render_template(
        'money_spent.html',
        values=values,
        total=total,
        month=now.strftime('%B'),
        year=now.year
    )

@app.route('/scrape-ingredients', methods=['POST'])
def scrape_ingredients():
    username = session.get('username')
    if not username:
        return jsonify({"msg": "You must be logged in to add ingredients to your grocery list"}), 401

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

    # all recipes are grabbed from foodista.com, so we can use the same selector for all recipes
    ingredients = soup.find_all(attrs={"itemprop": "ingredients"})
    for i in ingredients:
        #check to see if the ingredients last letter is :, if so do not add it to the grocery list
        if i.text.strip().lower()[-1] == ":":
            pass
        else:
            db.users.update_one({"username": username}, {"$push": {"grocery_list": i.text.strip().lower()}})

    if not ingredients:
        return jsonify({"msg": "No ingredients found"}), 404

    # Add ingredients to the grocery list
    return jsonify({"msg": "Ingredients added to grocery list"}), 200

def get_cached_daily_spoonacular_recipes():
    global daily_recipe_cache
    today = datetime.utcnow().strftime('%Y-%m-%d')

    if daily_recipe_cache["date"] == today and daily_recipe_cache["recipes"]:
        return daily_recipe_cache["recipes"]

    # Otherwise fetch new recipes
    api_key = os.getenv("SPOONACULAR_API_KEY")
    seed = int(datetime.utcnow().strftime('%Y%m%d'))
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
        return []  # Return empty if API call fails

# Register the blueprint
app.register_blueprint(user_routes, url_prefix='/')

if __name__ == "__main__":
    app.run(debug=True)