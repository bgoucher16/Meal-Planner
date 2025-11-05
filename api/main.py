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

@app.route('/subscription')
def subscription():
    return render_template('subscription.html')

@app.route

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

    if not diet:
        diet = None
    if not allergies:
        allergies = None
    if not monthley_budget:
        monthley_budget = None

    hashed_password = generate_password_hash(password)
    user_resp = supabase.table("users").insert({
        "username": username,
        "email": email,
        "password": hashed_password,
    }).execute()

    user_id = user_resp.data[0]["id"]

    
    user_tier = "free"
    total_swipes = 5

    supabase.table("user_profile").insert({
        "user_id": user_id,
        "location": location,
        "diet": diet,
        "allergies": allergies,
        "monthly_budget": monthley_budget,
        "user_tier": user_tier,
        "total_swipes": total_swipes,
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

    # Check for admin credentials
    if username == admin_username and password == admin_password:
        session.clear()
        session['is_admin'] = True
        flash("Admin login successful", "success")
        return redirect(url_for('show_admin'))

    if not username or not password:
        flash("Username and password are required", "error")
        return redirect(url_for('show_login'))

    # Query Supabase for the user
    user_resp = supabase.table("users").select("*").eq("username", username).execute()
    users = user_resp.data if user_resp.data else []

    if not users:
        flash("User not found", "error")
        return redirect(url_for('show_login'))

    user = users[0]

    # Verify password
    if not check_password_hash(user['password'], password):
        flash("Invalid username or password", "error")
        return redirect(url_for('show_login'))

    # Store user info in session
    session.clear()
    session['user_id'] = user['id']          # UUID from Supabase
    session['username'] = user['username']   # optional (for display)
    session['email'] = user['email']         # optional
    access_token = create_access_token(identity=user['id'])
    session['access_token'] = access_token

    flash("Login successful", "success")
    return redirect(url_for('show_home'))

@app.route('/admin')
def show_admin():
    return render_template('admin.html')

@app.route('/grocery-list')
def grocery_list():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to view your grocery list", "error")
        return redirect(url_for('show_login'))

    grocery_resp = supabase.table("grocery_list") \
        .select("ingredient_name, quantity, unit, recipe_id") \
        .eq("user_id", user_id) \
        .execute()

    groceries = grocery_resp.data
    return render_template('grocery_list.html', groceries=groceries)


# --- Helper function ---
def normalize_record(record):
    """Ensure Supabase record fields are always dictionaries."""
    if not record:
        return {"spending": {}, "archive": {}}
    for key in ["spending", "archive"]:
        if isinstance(record.get(key), list):
            record[key] = record[key][0] if record[key] else {}
        elif not isinstance(record.get(key), dict):
            record[key] = {}
    return record


# --- Main route: Money Spent ---
@app.route('/money-spent', methods=['GET', 'POST'])
def money_spent():
    username = session.get('username')
    if not username:
        flash("You must be logged in", "error")
        return redirect(url_for('show_login'))

    now = datetime.datetime.now()
    month_key = f"{now.year}-{now.month:02d}"

    # Fetch or create record
    resp = supabase.table("spending").select("*").eq("username", username).execute()
    record = normalize_record(resp.data[0] if resp.data else None)

    if not resp.data:
        supabase.table("spending").insert({
            "username": username,
            "spending": {},
            "archive": {}
        }).execute()

    # Handle POST (adding a new spending entry)
    if request.method == 'POST':
        amount = request.form.get('amount')
        if not amount or not amount.replace('.', '', 1).isdigit():
            flash("Please enter a valid amount", "error")
            return redirect(url_for('money_spent'))

        amount = float(amount)
        record['spending'].setdefault(month_key, [])
        record['spending'][month_key].append({
            "amount": amount,
            "date": now.strftime('%Y-%m-%d')
        })

        # Update database
        supabase.table("spending").update({
            "spending": record["spending"]
        }).eq("username", username).execute()

        flash("Spending recorded successfully", "success")
        # Refresh record after update
        resp = supabase.table("spending").select("*").eq("username", username).execute()
        record = normalize_record(resp.data[0])

    # Compute totals for display
    monthly_spending = {}
    for month, values in record["spending"].items():
        monthly_spending[month] = sum(v.get("amount", 0) for v in values)
    for month, values in record["archive"].items():
        monthly_spending[month] = monthly_spending.get(month, 0) + sum(
            v.get("amount", 0) if isinstance(v, dict) else v for v in values
        )

    current_total = monthly_spending.get(month_key, 0.0)

    return render_template(
        'money_spent.html',
        monthly_spending=monthly_spending,
        current_total=current_total,
        month=now.strftime('%B'),
        year=now.year
    )


# --- Reset route: Archive and clear current month ---
@app.route('/money-spent/reset', methods=['POST'])
def reset_money_spent():
    username = session.get('username')
    if not username:
        flash("You must be logged in", "error")
        return redirect(url_for('show_login'))

    now = datetime.datetime.now()
    month_key = f"{now.year}-{now.month:02d}"

    # Fetch record
    resp = supabase.table("spending").select("*").eq("username", username).execute()
    record = normalize_record(resp.data[0] if resp.data else None)

    if month_key not in record["spending"]:
        flash(f"No spending data found for {now.strftime('%B %Y')}.", "error")
        return redirect(url_for('money_spent'))

    # Move this month's spending to archive
    month_data = record["spending"].pop(month_key)
    record["archive"].setdefault(month_key, []).extend(month_data)

    # Update Supabase
    supabase.table("spending").update({
        "spending": record["spending"],
        "archive": record["archive"]
    }).eq("username", username).execute()

    # Re-fetch for accurate totals
    updated = supabase.table("spending").select("*").eq("username", username).execute()
    record = normalize_record(updated.data[0])

    flash(f"Spending for {now.strftime('%B %Y')} has been reset and archived.", "success")
    monthly_spending = {}
    for month, values in record["spending"].items():
        monthly_spending[month] = sum(v.get("amount", 0) for v in values)
    for month, values in record["archive"].items():
        monthly_spending[month] = monthly_spending.get(month, 0) + sum(
            v.get("amount", 0) if isinstance(v, dict) else v for v in values
        )

    current_total = monthly_spending.get(month_key, 0.0)

    return render_template(
        'money_spent.html',
        monthly_spending=monthly_spending,
        current_total=current_total,
        month=now.strftime('%B'),
        year=now.year
    )


@app.route('/search-user')
def search_user():
    username = request.args.get('user')
    if not username:
        flash("Please enter a username", "error")
        return redirect(url_for('show_admin'))

    # Get the user's account
    user_resp = supabase.table("users").select("*").eq("username", username).execute()
    user = user_resp.data[0] if user_resp.data else None

    if not user:
        flash("User not found", "error")
        return redirect(url_for('show_admin'))

    # Get the user's spending record
    spending_resp = supabase.table("spending").select("*").eq("username", username).execute()
    spending_data = spending_resp.data[0] if spending_resp.data else None

    monthly_spending = {}
    if spending_data:
        # Ensure spending and archive are dicts, not lists
        spending = spending_data.get("spending", {})
        archive = spending_data.get("archive", {})

        if isinstance(spending, list):
            spending = spending[0] if spending else {}

        if isinstance(archive, list):
            archive = archive[0] if archive else {}

        # Combine totals from spending and archive
        for month, values in spending.items():
            monthly_spending[month] = sum(
                [v["amount"] if isinstance(v, dict) else v for v in values]
            )

        for month, values in archive.items():
            monthly_spending[month] = monthly_spending.get(month, 0) + sum(
                [v if isinstance(v, (int, float)) else v.get("amount", 0) for v in values]
            )

    # Render admin template with user + monthly totals
    return render_template(
        'admin.html',
        user=user,
        monthly_spending=monthly_spending or {},
        selected_user=username
    )


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



#Everything recipes will be here
@app.route('/next-recipe')
def next_recipe():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to view recipes", "error")
        return redirect(url_for('show_login'))

    recipe_api_key = os.getenv("SPOONACULAR_API_KEY")

    # Get all Spoonacular IDs the user has already seen or favorited
    seen_resp = supabase.table("seen_recipes").select("spoonacular_id").eq("user_id", user_id).execute()
    favorite_resp = supabase.table("favorites").select("spoonacular_id").eq("user_id", user_id).execute()

    seen_ids = {r['spoonacular_id'] for r in seen_resp.data}
    favorite_ids = {r['spoonacular_id'] for r in favorite_resp.data}
    exclude_ids = seen_ids.union(favorite_ids)

    # Check to see if they have used any swipes today
    total_swipes = supabase.table("user_profile").select("total_swipes").eq("user_id", user_id).execute()
    
    # If no swipes left, redirect to home with message
    if total_swipes.data and total_swipes.data[0].get("total_swipes", 0) <= 0:
        flash("You have used all your swipes for today. Please upgrade your plan or wait until tomorrow!", "info")
        return redirect(url_for('show_home'))


    # Build query to Spoonacular to fetch random recipes
    url = f"https://api.spoonacular.com/recipes/random?number=10&apiKey={recipe_api_key}"
    response = requests.get(url)

    if response.status_code != 200:
        flash("Failed to fetch recipes", "error")
        return redirect(url_for('dashboard'))

    recipes = response.json().get('recipes', [])
    
    # Filter out recipes the user already saw/favorited
    unseen_recipes = [r for r in recipes if r['id'] not in exclude_ids]

    if not unseen_recipes:
        flash("No new recipes to show right now — check back later!", "info")
        return redirect(url_for('dashboard'))

    recipe = unseen_recipes[0]  # Show one recipe at a time

    return render_template('swipe_recipe.html', recipe=recipe)


@app.route('/favorite/<int:spoonacular_id>', methods=['POST'])
def favorite(spoonacular_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to favorite recipes", "error")
        return redirect(url_for('show_login'))

    api_key = os.getenv("SPOONACULAR_API_KEY")

    # Step 1️⃣: Add to favorites (if not already there)
    existing_fav = supabase.table("favorites") \
        .select("id") \
        .eq("user_id", user_id) \
        .eq("spoonacular_id", spoonacular_id) \
        .execute()

    if not existing_fav.data:
        supabase.table("favorites").insert({
            "user_id": user_id,
            "spoonacular_id": spoonacular_id
        }).execute()

    # Step 2️⃣: Mark as seen
    existing_seen = supabase.table("seen_recipes") \
        .select("id") \
        .eq("user_id", user_id) \
        .eq("spoonacular_id", spoonacular_id) \
        .execute()

    if not existing_seen.data:
        supabase.table("seen_recipes").insert({
            "user_id": user_id,
            "spoonacular_id": spoonacular_id
        }).execute()

    # Step 3️⃣: Cache the recipe if not already cached
    cache_check = supabase.table("cached_recipes") \
        .select("spoonacular_id") \
        .eq("spoonacular_id", spoonacular_id) \
        .execute()

    if not cache_check.data:
        url = f"https://api.spoonacular.com/recipes/{spoonacular_id}/information?apiKey={api_key}"
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            supabase.table("cached_recipes").insert({
                "spoonacular_id": data["id"],
                "title": data.get("title", ""),
                "image": data.get("image", ""),
                "summary": data.get("summary", ""),
                "ingredients": data.get("extendedIngredients", []),
                "instructions": data.get("instructions", ""),
            }).execute()

    flash("Recipe added to favorites!", "success")

    # Update user's remaining swipes
    profile_resp = supabase.table("user_profile").select("total_swipes").eq("user_id", user_id).execute()
    if profile_resp.data:
        current_swipes = profile_resp.data[0].get("total_swipes", 0)
        if current_swipes > 0:
            supabase.table("user_profile").update({
                "total_swipes": current_swipes - 1
            }).eq("user_id", user_id).execute()
        if current_swipes == 0:
            flash("You have used all your swipes for today. Please upgrade your plan or wait until tomorrow!", "info")
            return redirect(url_for('show_home'))

    return redirect(url_for('next_recipe'))


@app.route('/dislike/<int:spoonacular_id>', methods=['POST'])
def dislike(spoonacular_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('show_login'))

    # Just mark as seen
    supabase.table("seen_recipes").insert({
        "user_id": user_id,
        "spoonacular_id": spoonacular_id
    }).execute()

    return redirect(url_for('next_recipe'))

@app.route('/skip/<int:spoonacular_id>', methods=['POST'])
def skip(spoonacular_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('show_login'))

    # Optionally record skip in a separate table, or treat it as seen
    supabase.table("seen_recipes").insert({
        "user_id": user_id,
        "spoonacular_id": spoonacular_id
    }).execute()

    profile_resp = supabase.table("user_profile").select("total_swipes").eq("user_id", user_id).execute()
    if profile_resp.data:
        current_swipes = profile_resp.data[0].get("total_swipes", 0)
        if current_swipes > 0:
            supabase.table("user_profile").update({
                "total_swipes": current_swipes - 1
            }).eq("user_id", user_id).execute()

    return redirect(url_for('next_recipe'))


@app.route('/favorite-recipes')
def favorite_recipes():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to view your favorites", "error")
        return redirect(url_for('show_login'))

    # Step 1️⃣: Fetch all spoonacular_ids the user has favorited
    fav_resp = supabase.table("favorites") \
        .select("spoonacular_id") \
        .eq("user_id", user_id) \
        .execute()

    favorite_ids = [fav['spoonacular_id'] for fav in fav_resp.data]

    if not favorite_ids:
        flash("You have no favorite recipes yet.", "info")
        return render_template('favorite_recipes.html', favorites=[])

    # Step 2️⃣: Fetch all cached recipes that match those IDs
    cached_recipes_resp = supabase.table("cached_recipes") \
        .select("*") \
        .in_("spoonacular_id", favorite_ids) \
        .execute()

    recipes = cached_recipes_resp.data if cached_recipes_resp.data else []

    # Step 3️⃣: Render locally cached recipes
    return render_template('favorite_recipes.html', favorites=recipes)




@app.route('/unfavorite/<int:spoonacular_id>', methods=['POST'])
def unfavorite_recipe(spoonacular_id):
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('show_login'))

    supabase.table("favorites").delete().eq("user_id", user_id).eq("spoonacular_id", spoonacular_id).execute()
    flash("Recipe removed from favorites", "info")
    return redirect(url_for('favorite_recipes'))


@app.route('/add-to-grocery/<int:spoonacular_id>', methods=['POST'])
def add_to_grocery(spoonacular_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to add groceries", "error")
        return redirect(url_for('show_login'))

    api_key = os.getenv("SPOONACULAR_API_KEY")
    url = f"https://api.spoonacular.com/recipes/{spoonacular_id}/information?apiKey={api_key}"
    response = requests.get(url)

    if response.status_code != 200:
        flash("Failed to fetch recipe details.", "error")
        return redirect(url_for('favorite_recipes'))

    recipe_data = response.json()
    ingredients = recipe_data.get("extendedIngredients", [])

    added_count = 0
    for ing in ingredients:
        name = ing.get("nameClean") or ing.get("name") or "Unknown"
        amount = str(ing.get("amount", ""))
        unit = ing.get("unit", "")

        # Check if already exists in user's grocery list
        existing = supabase.table("grocery_list") \
            .select("id") \
            .eq("user_id", user_id) \
            .eq("ingredient_name", name) \
            .execute()

        if not existing.data:
            supabase.table("grocery_list").insert({
                "user_id": user_id,
                "ingredient_name": name,
                "quantity": amount,
                "unit": unit,
                "recipe_id": spoonacular_id
            }).execute()
            added_count += 1

    flash(f"Added {added_count} new items to your grocery list!", "success")
    return redirect(url_for('favorite_recipes'))


@app.route('/remove-grocery-item/<uuid:item_id>', methods=['POST'])
def remove_grocery_item(item_id):
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in to modify your grocery list", "error")
        return redirect(url_for('show_login'))

    # Ensure the user only deletes their own item
    supabase.table("grocery_list") \
        .delete() \
        .eq("id", str(item_id)) \
        .eq("user_id", user_id) \
        .execute()

    flash("Item removed from grocery list", "info")
    return redirect(url_for('grocery_list'))


if __name__ == '__main__':
    app.run(debug=True)