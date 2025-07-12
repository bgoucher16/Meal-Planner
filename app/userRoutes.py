from flask import Blueprint, request, jsonify, render_template, redirect, url_for, session, flash
from pymongo import MongoClient
from flask_jwt_extended import jwt_required
import requests
import os
import random
from datetime import datetime

user_routes = Blueprint('user_routes', __name__)

# MongoDB setup
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client.meal_planner_db

# Cache object
daily_recipe_cache = {
    "date": None,
    "recipes": []
}

def get_cached_daily_spoonacular_recipes():
    """Fetch 5 daily random Spoonacular recipes and cache them for 24 hours."""
    global daily_recipe_cache
    today = datetime.utcnow().strftime('%Y-%m-%d')

    if daily_recipe_cache["date"] == today and daily_recipe_cache["recipes"]:
        return daily_recipe_cache["recipes"]

    # Otherwise fetch new
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
        return []

@user_routes.route('/')
def show_home():
    username = session.get('username')
    if not username:
        flash("You must be logged in to view the home page", "error")
        return redirect(url_for('login'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('login'))

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

@user_routes.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)
    session.pop('access_token', None)
    flash("Logged out successfully", "success")
    return redirect(url_for('login'))

@user_routes.route('/register', methods=['GET'])
def show_register():
    return render_template('register.html')

@user_routes.route('/login', methods=['GET'])
def show_login():
    return render_template('login.html')

@user_routes.route('/admin', methods=['GET'])
def show_admin():
    return render_template('admin.html')

@user_routes.route('/grocery-list', methods=['GET'])
def show_grocery_list():
    username = session.get('username')
    if not username:
        flash("You must be logged in to view your grocery list", "error")
        return redirect(url_for('login'))

    user = db.users.find_one({"username": username})
    grocery_list = user.get('grocery_list', [])
    return render_template('grocery_list.html', grocery_list=grocery_list)

@user_routes.route('/favorites', methods=['GET'])
def show_favorites():
    username = session.get('username')
    if not username:
        flash("You must be logged in to view your favorites", "error")
        return redirect(url_for('login'))

    user = db.users.find_one({"username": username})
    favorites = user.get('favorites', [])
    return render_template('favorites.html', favorites=favorites)

@user_routes.route('/recipes', methods=['GET'])
def show_recipes():
    return render_template('recipes.html')

@user_routes.route('/money-spent', methods=['GET'])
def show_money_spent():
    return render_template('money_spent.html')

@user_routes.route('/search-recipes', methods=['GET'])
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
        # for each recipe check to see if any of the ingredients are in the users allegeries
        username = session.get('username')
        user = db.users.find_one({"username": username})
        if user and 'allergies' in user:
            allergies = user['allergies']
            for recipe in recipes:
                recipe['has_allergy'] = any(allergy.lower() in (ingredient.lower() for ingredient in recipe.get('extendedIngredients', [])) for allergy in allergies)
        else:
            for recipe in recipes:
                recipe['has_allergy'] = False

        return render_template('recipes.html', recipes=recipes, ingredient=ingredient)
    else:
        flash("Failed to fetch recipes", "error")
        return redirect(url_for('show_recipes'))

@user_routes.route('/search-user', methods=['GET'])
def search_user():
    username = request.args.get('user')
    if not username:
        flash("Please enter a username", "error")
        return redirect(url_for('user_routes.show_admin'))

    user = db.users.find_one({"username": username})
    if not user:
        flash("User not found", "error")
        return redirect(url_for('user_routes.show_admin'))

    # Get all spending data for this user
    spending_record = db.spending.find_one({"username": username})
    monthly_spending = {}
    if spending_record and "spending" in spending_record:
        for month, values in spending_record["spending"].items():
            monthly_spending[month] = sum(values)
    if spending_record and "archive" in spending_record:
        for month, values in spending_record["archive"].items():
            if month not in monthly_spending:
                monthly_spending[month] = 0
            monthly_spending[month] += sum(values)

    return render_template(
        'admin.html',
        user=user,
        monthly_spending=monthly_spending if monthly_spending else None
    )