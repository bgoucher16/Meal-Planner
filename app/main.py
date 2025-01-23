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

    if not username or not email or not password or not confirm_password or not location:
        flash("All fields are required", "error")
        return redirect(url_for('show_register'))

    if password != confirm_password:
        flash("Passwords do not match", "error")
        return redirect(url_for('show_register'))

    if db.users.find_one({"username": username}):
        flash("Username already exists", "error")
        return redirect(url_for('show_register'))

    if db.users.find_one({"email": email}):
        flash("Email already exists", "error")
        return redirect(url_for('show_register'))

    hashed_password = generate_password_hash(password)
    db.users.insert_one({"username": username, "email": email, "password": hashed_password, "location": location})
    flash("User registered successfully", "success")
    return redirect(url_for('show_login'))

@app.route('/login', methods=['POST'])
def login():
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

#User Routing

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
    return render_template('home.html', grocery_list=grocery_list, favorites=favorites)

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)
    session.pop('access_token', None)
    flash("Logged out successfully", "success")
    return redirect(url_for('show_login'))

@app.route('/register', methods=['GET'])
def show_register():
    return render_template('register.html')

@app.route('/login', methods=['GET'])
def show_login():
    return render_template('login.html')

@app.route('/admin', methods=['GET'])
def show_admin():
    return render_template('admin.html')

@app.route('/grocery-list', methods=['GET'])
def show_grocery_list():
    username = session.get('username')
    if not username:
        flash("You must be logged in to view your grocery list", "error")
        return redirect(url_for('show_login'))

    user = db.users.find_one({"username": username})
    grocery_list = user.get('grocery_list', [])
    return render_template('grocery_list.html', grocery_list=grocery_list)

@app.route('/favorites', methods=['GET'])
def show_favorites():
    username = session.get('username')
    if not username:
        flash("You must be logged in to view your favorites", "error")
        return redirect(url_for('show_login'))

    user = db.users.find_one({"username": username})
    favorites = user.get('favorites', [])
    return render_template('favorites.html', favorites=favorites)

@app.route('/recipes', methods=['GET'])
def show_recipes():
    return render_template('recipes.html')

@app.route('/grocery-list-add', methods=['POST'])
def grocery_list_add():
    username = session.get('username')
    if not username:
        flash("You must be logged in to add items to your grocery list", "error")
        return redirect(url_for('show_login'))
    
    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('show_login'))

    # Initialize grocery_list if it doesn't exist
    if "grocery_list" not in user:
        db.users.update_one({"username": username}, {"$set": {"grocery_list": []}})

    # Get and validate the item
    item = request.form.get('item', '').strip().lower()
    if not item:
        flash("Item is required", "error")
        return redirect(url_for('show_grocery_list'))
    
    if item in user['grocery_list']:
        flash("Item already exists in grocery list", "error")
        return redirect(url_for('show_grocery_list'))
    
    # Add item to the grocery list
    db.users.update_one({"username": username}, {"$push": {"grocery_list": item}})
    flash("Item added to grocery list", "success")
    return redirect(url_for('show_grocery_list'))

#for readding favorite items to the grocery list whilst staying on the favorites page
@app.route('/grocery-list-add-favorites', methods=['POST'])
def grocery_list_add_favorites():
    username = session.get('username')
    if not username:
        flash("You must be logged in to add items to your grocery list", "error")
        return redirect(url_for('show_login'))
    
    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('show_login'))

    # Initialize grocery_list if it doesn't exist
    if "grocery_list" not in user:
        db.users.update_one({"username": username}, {"$set": {"grocery_list": []}})

    # Get and validate the item
    item = request.form.get('item', '').strip().lower()
    if not item:
        flash("Item is required", "error")
        return redirect(url_for('show_favorites'))
    
    if item in user['grocery_list']:
        flash("Item already exists in grocery list", "error")
        return redirect(url_for('show_favorites'))
    
    # Add item to the grocery list
    db.users.update_one({"username": username}, {"$push": {"grocery_list": item}})
    flash("Item added to grocery list", "success")
    return redirect(url_for('show_favorites'))

@app.route('/grocery-list-delete', methods=['POST'])
def grocery_list_delete():
    username = session.get('username')
    if not username:
        flash("You must be logged in to delete items from your grocery list", "error")
        return redirect(url_for('show_login'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('show_login'))

    # Get and validate the item
    item = request.form.get('item', '').strip().lower()
    if not item:
        flash("Item is required", "error")
        return redirect(url_for('show_grocery_list'))

    # Delete item from the grocery list
    db.users.update_one({"username": username}, {"$pull": {"grocery_list": item}})
    flash("Item deleted from grocery list", "success")
    return redirect(url_for('show_grocery_list'))

@app.route('/grocery-list-favorite', methods=['POST'])
def grocery_list_favorite():
    username = session.get('username')
    if not username:
        flash("You must be logged in to favorite items from your grocery list", "error")
        return redirect(url_for('show_login'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('show_login'))

    # Get and validate the item
    item = request.form.get('item', '').strip().lower()
    if not item:
        flash("Item is required", "error")
        return redirect(url_for('show_grocery_list'))

    # Add item to the favorites list
    if "favorites" not in user:
        db.users.update_one({"username": username}, {"$set": {"favorites": []}})

    if item in user["favorites"]:
        flash("Item already favorited", "error")
        return redirect(url_for('show_grocery_list'))
    
    db.users.update_one({"username": username}, {"$push": {"favorites": item}})
    flash("Item favorited", "success")
    return redirect(url_for('show_grocery_list'))

@app.route('/grocery-list-unfavorite', methods=['POST'])
def grocery_list_unfavorite():
    username = session.get('username')
    if not username:
        flash("You must be logged in to unfavorite items from your grocery list", "error")
        return redirect(url_for('show_login'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('show_login'))

    # Get and validate the item
    item = request.form.get('item', '').strip().lower()
    if not item:
        flash("Item is required", "error")
        return redirect(url_for('show_grocery_list'))

    # Remove item from the favorites list
    db.users.update_one({"username": username}, {"$pull": {"favorites": item}})
    flash("Item unfavorited", "success")
    return redirect(url_for('show_favorites'))


@app.route('/search-recipes', methods=['GET'])
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
        return render_template('recipes.html', recipes=recipes, ingredient=ingredient)
    else:
        flash("Failed to fetch recipes", "error")
        return redirect(url_for('show_recipes'))
    

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


@app.route('/search-user', methods=['GET'])
def search_user():
    username = request.args.get('user')
    if not username:
        flash("Please enter a username", "error")
        return redirect(url_for('show_admin'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('show_admin'))

    return render_template('admin.html', user=user)

if __name__ == "__main__":
    app.run(debug=True)