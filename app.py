from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import bcrypt
import yfinance as yf
from datetime import datetime, timedelta
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from random import sample
import pyotp
import os
from functools import wraps

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Use environment variable for secret key in production
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')
os.environ['SUPERADMIN_SECRET_KEY'] = 'StrongKey99'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Models (unchanged)
class AdminRole(db.Model):
    __tablename__ = 'admin_role'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role_type = db.Column(db.String(50), nullable=False)  # Finance, Support, Moderator

class Issue(db.Model):
    __tablename__ = 'issue'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, assigned, resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200), nullable=False)
    balance = db.Column(db.Float, default=10000)
    is_admin = db.Column(db.Boolean, default=False)
    admin_role = db.relationship('AdminRole', backref='user', uselist=False)
    is_superadmin = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=True)
    trades = db.relationship('Trade', backref='user', lazy=True)

    def __init__(self, email, password, name, is_admin=False, is_superadmin=False, is_approved=True):
        self.name = name
        self.email = email
        self.password = generate_password_hash(password, method='pbkdf2:sha256')
        self.is_admin = is_admin
        self.is_superadmin = is_superadmin
        self.is_approved = is_approved

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def init_db():
        with app.app_context():
            db.create_all()
            create_superadmin()

class Trade(db.Model):
    __tablename__ = 'trade'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    stock_symbol = db.Column(db.String(10), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    action = db.Column(db.String(4), nullable=False)  # 'buy' or 'sell'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class QuizQuestion(db.Model):
    __tablename__ = 'quiz_question'
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(500), nullable=False)
    option_a = db.Column(db.String(200), nullable=False)
    option_b = db.Column(db.String(200), nullable=False)
    option_c = db.Column(db.String(200), nullable=False)
    option_d = db.Column(db.String(200), nullable=False)
    correct_answer = db.Column(db.String(1), nullable=False)

# Helper functions (unchanged)
def get_stock_data(symbol):
    try:
        stock = yf.Ticker(symbol)
        
        # 1. Company Profile Data
        info = stock.info
        company_info = {
            "name": info.get("longName", symbol.upper()),
            "sector": info.get("sector", "N/A"),
            "industry": info.get("industry", "N/A"),
            "market_cap": info.get("marketCap", 0),
            "employees": info.get("fullTimeEmployees", "N/A"),
            "website": info.get("website", "#"),
            "ceo": info.get("companyOfficers", [{}])[0].get("name", "N/A")
        } if info else None

        # 2. Historical Data (5 days)
        historical = stock.history(period="5d")
        historical_data = []
        if not historical.empty:
            historical = historical.reset_index()
            historical['Date'] = historical['Date'].dt.strftime('%Y-%m-%d')
            historical_data = historical[['Date', 'Open', 'High', 'Low', 'Close']].to_dict('records')

        # 3. Candlestick Data (Intraday) - Corrected timezone handling
        candles = stock.history(period="1d", interval="1m")
        candles_data = []
        current_price = None

        if not candles.empty:
            try:
                # Step 1: Localize to UTC (if not already localized)
                candles = candles.tz_localize('UTC', ambiguous='infer')

                # Step 2: Filter out weekends (Saturday=5, Sunday=6) in UTC
                candles = candles[candles.index.dayofweek < 5]

                # Step 3: Convert to IST
                candles = candles.tz_convert('Asia/Kolkata')

                # Step 4: Filter market hours (9:15 AM to 3:30 PM IST)
                candles = candles.between_time('09:15', '15:30')

                # Step 5: Format datetime and reset index
                candles = candles.reset_index()
                candles['Datetime'] = candles['Datetime'].dt.strftime('%Y-%m-%d %H:%M')

                # Step 6: Extract data
                current_price = candles['Close'].iloc[-1] if not candles.empty else None
                candles_data = candles[['Datetime', 'Open', 'High', 'Low', 'Close']].to_dict('records')

            except Exception as e:
                print(f"Error processing candles: {str(e)}")
                # Fallback to raw UTC data
                candles = candles.reset_index()
                if 'Datetime' in candles.columns:
                    candles['Datetime'] = candles['Datetime'].dt.strftime('%Y-%m-%d %H:%M')
                current_price = candles['Close'].iloc[-1] if not candles.empty else None
                candles_data = candles[['Datetime', 'Open', 'High', 'Low', 'Close']].to_dict('records')

        return {
            'company_info': company_info,
            'historical': historical_data,
            'candles': candles_data,
            'current_price': current_price,
            'symbol': symbol
        }
        
    except Exception as e:
        print(f"Data fetch error: {str(e)}")
        return {
            'company_info': None,
            'historical': [],
            'candles': [],
            'current_price': None,
            'symbol': symbol
        }
        # Add this right after get_stock_data() function
def get_stock_price(symbol):
    """Get current stock price for a given symbol"""
    try:
        stock = yf.Ticker(symbol)
        data = stock.history(period="max")
        if not data.empty:
            return round(data['Close'].iloc[-1], 2)
        return None
    except Exception as e:
        print(f"Error getting price for {symbol}: {str(e)}")
        return None
        
def calculate_portfolio_positions(trades):
    positions = defaultdict(lambda: {'shares': 0, 'total_cost': 0})

    for trade in trades:
        if trade.action == 'buy':
            positions[trade.stock_symbol]['shares'] += trade.quantity
            positions[trade.stock_symbol]['total_cost'] += trade.quantity * trade.price
        elif trade.action == 'sell':
            positions[trade.stock_symbol]['shares'] -= trade.quantity
            if positions[trade.stock_symbol]['shares'] > 0:
                cost_per_share = positions[trade.stock_symbol]['total_cost'] / (positions[trade.stock_symbol]['shares'] + trade.quantity)
                positions[trade.stock_symbol]['total_cost'] = positions[trade.stock_symbol]['shares'] * cost_per_share

    portfolio = []
    for symbol, data in positions.items():
        if data['shares'] > 0:
            current_price = get_stock_price(symbol) or 0  # Now using the helper function
            avg_price = data['total_cost'] / data['shares']
            total_value = data['shares'] * current_price
            profit_loss = total_value - data['total_cost']

            portfolio.append({
                'symbol': symbol,
                'shares': data['shares'],
                'avg_price': avg_price,
                'current_price': current_price,
                'total_value': total_value,
                'profit_loss': profit_loss
            })

    return portfolio

# Login required decorator (unchanged)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            flash("You need to log in first.", "warning")
            return redirect('/login')
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Add admin required decorator (unchanged)
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'is_admin' not in session or not session['is_admin']:
            flash('Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'is_superadmin' not in session or not session['is_superadmin']:
            flash('Super-Admin access required.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Ensure only one Super-Admin exists (unchanged)
def create_superadmin():
    superadmin_email = "somilbakshi11@gmail.com"
    superadmin_password = "Somil@123"

    existing_superadmin = User.query.filter_by(email=superadmin_email).first()

    if not existing_superadmin:
        hashed_password = generate_password_hash(superadmin_password, method='pbkdf2:sha256')
        new_superadmin = User(
            name="SuperAdmin",
            email=superadmin_email,
            password=hashed_password,  # Now hashed
            is_admin=True,
            is_superadmin=True,
            is_approved=True
        )

        db.session.add(new_superadmin)
        db.session.commit()
        print("Superadmin created successfully!")


@app.route('/about')
def about():
    return render_template('about.html')

# Template filters
@app.template_filter('number_format')
def number_format(value):
    try:
        if value is None:
            return 'N/A'
        return f"{float(value):,.2f}"
    except (ValueError, TypeError):
        return 'N/A'

# Routes
@app.route('/')
def landing():
    return render_template('start.html')

@app.route('/start')
def start_page():
    return render_template('start.html')


@app.route('/play')
def play():
    return redirect(url_for('home'))

@app.route('/index')
def home():
    return render_template('index.html')


@app.route('/how-to-play')
def how_to_play():
    return render_template('howtoplay.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        try:
            name = request.form['name'].strip().lower()
            email = request.form['email'].strip().lower()
            password = request.form['password']
            account_type = request.form['account_type']

            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                flash("Email already exists. Please use a different email.", "danger")
                return render_template('signup.html', name=name, email=email)

            new_user = User(
                name=name.capitalize(),
                email=email,
                password=password,
                is_admin=(account_type == 'admin'),
                is_superadmin=False,  # Super admin signup is handled separately
                is_approved=(account_type != 'admin')  # Pending approval for admin
            )

            db.session.add(new_user)
            db.session.commit()

            flash("Account created successfully!", "success")
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            print(f"Error in signup: {e}")
            flash("Error creating account. Please try again.", "danger")
            return render_template('signup.html')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password'].strip()

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['email'] = user.email
            session['is_admin'] = user.is_admin
            session['is_superadmin'] = user.is_superadmin
            session['name'] = user.name

            flash('Successfully logged in!', 'success')

            if user.is_superadmin:
                return redirect(url_for('superadmin_dashboard'))
            elif user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('profile'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')

@app.route('/superadminsignup', methods=['GET', 'POST'])
def superadmin_signup():
    if request.method == 'POST':
        name = request.form['name'].strip().lower()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        secret_key = request.form.get('secret_key', '')

        # Validate the secret key
        SUPERADMIN_SECRET_KEY = os.environ.get('SUPERADMIN_SECRET_KEY', 'StrongKey99')
        if secret_key != SUPERADMIN_SECRET_KEY:
            flash("Invalid secret key for Super Admin creation.", "danger")
            return render_template('superadminsignup.html')

        # Check if a super admin already exists
        existing_superadmin = User.query.filter_by(is_superadmin=True).first()
        if existing_superadmin:
            flash("A Super Admin already exists.", "danger")
            return render_template('superadminsignup.html')

        # Create the new super admin user
        new_user = User(
            name=name.capitalize(),
            email=email,
            password=password,
            is_admin=True,
            is_superadmin=True,
            is_approved=True
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Super Admin account created successfully!", "success")
        return redirect(url_for('login'))

    return render_template('superadminsignup.html')

# Super-Admin Dashboard
@app.route('/superadmin')
@login_required
@superadmin_required
def superadmin_dashboard():
    pending_admins = User.query.filter_by(is_admin=True, is_approved=False).all()
    approved_admins = User.query.filter(
        User.is_admin == True,
        User.is_approved == True,
        User.id != session['user_id']
    ).all()
    users = User.query.filter_by(is_admin=False).all()
    issues = Issue.query.filter_by(status='pending').all()
    
    return render_template('superadmin.html',
                         pending_admins=pending_admins,
                         approved_admins=approved_admins,
                         users=users,
                         issues=issues)

# Add new routes to handle AJAX requests
@app.route('/approve_admin', methods=['POST'])
@login_required
@superadmin_required
def approve_admin_with_role():
    admin_id = request.form.get('admin_id')
    role = request.form.get('role')
    
    admin = User.query.get_or_404(admin_id)
    if admin.is_admin and not admin.is_approved:
        admin.is_approved = True
        
        # Create admin role
        new_role = AdminRole(user_id=admin_id, role_type=role)
        db.session.add(new_role)
        
        try:
            db.session.commit()
            return jsonify({'message': 'Admin approved successfully with role: ' + role})
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Error approving admin: ' + str(e)}), 500
    
    return jsonify({'message': 'Invalid admin ID or already approved'}), 400

@app.route('/reject_admin', methods=['POST'])
@login_required
@superadmin_required
def reject_admin_ajax():
    admin_id = request.form.get('admin_id')
    admin = User.query.get_or_404(admin_id)
    
    if admin.is_admin and not admin.is_approved:
        try:
            db.session.delete(admin)
            db.session.commit()
            return jsonify({'message': 'Admin rejected successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Error rejecting admin: ' + str(e)}), 500
    
    return jsonify({'message': 'Invalid admin ID or already processed'}), 400

@app.route('/assign_issue', methods=['POST'])
@login_required
@superadmin_required
def assign_issue():
    issue_id = request.form.get('issue_id')
    admin_id = request.form.get('admin_id')
    
    issue = Issue.query.get_or_404(issue_id)
    admin = User.query.get_or_404(admin_id)
    
    if admin.is_admin and admin.is_approved:
        try:
            issue.assigned_to = admin_id
            issue.status = 'assigned'
            db.session.commit()
            return jsonify({'message': 'Issue assigned successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'message': 'Error assigning issue: ' + str(e)}), 500
    
    return jsonify({'message': 'Invalid admin ID'}), 400


# Modify the admin dashboard route
@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    try:
        # Get all users except the current admin
        users = User.query.filter(User.id != session['user_id']).all()
        
        # Get all trades
        trades = db.session.query(
            Trade, User.email
        ).join(User).order_by(Trade.timestamp.desc()).all()
        
        return render_template('admin.html', 
                             users=users, 
                             trades=trades)
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}', 'danger')
        return redirect(url_for('login'))

# Add admin actions
@app.route('/admin/delete_user/<int:user_id>')
@login_required
@admin_required
def delete_user(user_id):
    try:
        user = User.query.get_or_404(user_id)
        if user.is_admin:
            flash('Cannot delete admin users.', 'danger')
            return redirect(url_for('admin_dashboard'))
            
        # Delete user
        db.session.query(Trade).filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reset_user_balance/<int:user_id>')
@login_required
@admin_required
def reset_user_balance(user_id):
    try:
        user = User.query.get_or_404(user_id)
        user.balance = 10000  # Reset to initial balance
        db.session.commit()
        flash('User balance reset successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error resetting balance: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/profile')
@login_required
def profile():
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        session.clear()
        return redirect('/login')
    return render_template('profile.html', user=user)

@app.route('/delete-profile')
@login_required
def delete_profile():
    try:
        user = User.query.filter_by(email=session['email']).first()
        if user:
            # Delete all trades associated with the user
            Trade.query.filter_by(user_id=user.id).delete()
            # Delete the user
            db.session.delete(user)
            db.session.commit()
            session.clear()
            flash('Your account has been successfully deleted.', 'success')
            return redirect('/')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting account: {str(e)}', 'error')
        return redirect('/profile')

@app.route('/reset-data')
@login_required
def reset_data():
    try:
        user = User.query.filter_by(email=session['email']).first()
        if user:
            # Delete all trades associated with the user
            Trade.query.filter_by(user_id=user.id).delete()
            # Reset user balance to initial amount
            user.balance = 10000
            db.session.commit()
            flash('Your trade data has been reset successfully.', 'success')
            return redirect('/profile')
    except Exception as e:
        db.session.rollback()
        flash(f'Error resetting trade data: {str(e)}', 'error')
        return redirect('/profile')

@app.route('/trade', methods=['GET', 'POST'])
@login_required
def trade():
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect('/login')

    context = {
        'user': user,
        'stock_data': None,
        'historical_data': None,
        'candles_data': None,
        'company_info': None,
        'trade_success': None,
        'trade_error': None,
        'stock_info_error': None,
        'current_price': None,
        'selected_symbol': None
    }

    try:
        if request.method == 'POST':
            symbol = request.form.get('symbol', '').strip().upper()
            context['selected_symbol'] = symbol

            # Buying & Selling Stocks
            if 'action' in request.form:
                try:
                    quantity = int(request.form['quantity'])
                    if quantity <= 0:
                        flash('Invalid quantity', 'error')
                        return render_template('trade.html', **context)
                except ValueError:
                    flash('Invalid quantity', 'error')
                    return render_template('trade.html', **context)

                action = request.form['action']
                stock_price = get_stock_price(symbol)
                context['current_price'] = stock_price

                if stock_price is None:
                    context['trade_error'] = f"Could not retrieve data for stock symbol: {symbol}"
                else:
                    total_value = stock_price * quantity

                    if action == 'buy':
                        if user.balance >= total_value:
                            try:
                                user.balance -= total_value
                                trade = Trade(
                                    user_id=user.id,
                                    stock_symbol=symbol,
                                    quantity=quantity,
                                    price=stock_price,
                                    action='buy'
                                )
                                db.session.add(trade)
                                db.session.commit()
                                context['trade_success'] = f"Successfully bought {quantity} shares of {symbol} at ₹{stock_price} each."
                                flash(context['trade_success'], 'success')
                            except Exception as e:
                                db.session.rollback()
                                context['trade_error'] = f"Transaction failed: {str(e)}"
                        else:
                            context['trade_error'] = "Insufficient balance for this transaction."

                    elif action == 'sell':
                        trades = Trade.query.filter_by(user_id=user.id, stock_symbol=symbol).all()
                        shares_owned = sum(t.quantity if t.action == 'buy' else -t.quantity for t in trades)

                        if shares_owned >= quantity:
                            try:
                                user.balance += total_value
                                trade = Trade(
                                    user_id=user.id,
                                    stock_symbol=symbol,
                                    quantity=quantity,
                                    price=stock_price,
                                    action='sell'
                                )
                                db.session.add(trade)
                                db.session.commit()
                                context['trade_success'] = f"Successfully sold {quantity} shares of {symbol} at ₹{stock_price} each."
                                flash(context['trade_success'], 'success')
                            except Exception as e:
                                db.session.rollback()
                                context['trade_error'] = f"Transaction failed: {str(e)}"
                        else:
                            context['trade_error'] = f"Insufficient shares. You own {shares_owned} shares of {symbol}."

                    if context['trade_error']:
                        flash(context['trade_error'], 'error')

            # Fetching Stock Data & Company Info
            elif 'info_action' in request.form:
                symbol = request.form.get('info_symbol', '').strip().upper()
                context['selected_symbol'] = symbol
                stock_data = get_stock_data(symbol)

                if stock_data:
                    context['candles_data'] = stock_data.get('candles', [])
                    context['historical_data'] = stock_data.get('historical', [])
                    context['company_info'] = stock_data.get('company_info', {})
                    context['current_price'] = stock_data.get('current_price')

                    if not context['company_info']:
                        context['stock_info_error'] = f"Could not retrieve information for stock symbol: {symbol}"
                        flash(context['stock_info_error'], 'error')

    except Exception as e:
        print(f"Error in trade route: {e}")
        flash(f"An error occurred: {str(e)}", 'error')

    return render_template('trade.html', **context)


@app.route('/search_stocks')
def search_stocks():
    search_term = request.args.get('term', '').strip().upper()
    if not search_term:
        return jsonify([])

    # Fetch a list of stock symbols and names
    try:
        # Use yfinance to search for stocks
        ticker = yf.Ticker(search_term)
        info = ticker.info
        if info:
            # Return the symbol and name
            return jsonify([{
                'label': f"{info.get('symbol', '')} - {info.get('longName', '')}",
                'value': info.get('symbol', '')
            }])
        else:
            return jsonify([])
    except Exception as e:
        print(f"Error searching stocks: {e}")
        return jsonify([])

@app.route('/portfolio')
@login_required
def portfolio():
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect('/login')

    try:
        all_trades = Trade.query.filter_by(user_id=user.id).order_by(Trade.timestamp.desc()).all()
        
        # Separate buy and sell trades
        buy_trades = [t for t in all_trades if t.action == 'buy']
        sell_trades = [t for t in all_trades if t.action == 'sell']
        
        positions = calculate_portfolio_positions(all_trades)

        return render_template('portfolio.html',
                            user=user,
                            positions=positions,
                            buy_trades=buy_trades,
                            sell_trades=sell_trades)

    except Exception as e:
        print(f"Portfolio error: {str(e)}")
        flash("Error loading portfolio data", "error")
        return redirect(url_for('profile'))
    
@app.route('/crashcourse')
def crashcourse():
    return render_template('crashcourse.html')

@app.route('/quiz')
@login_required
def quiz():
    try:
        all_questions = QuizQuestion.query.all()
        if len(all_questions) < 10:
            flash("Not enough questions available for the quiz.", 'error')
            return redirect('/profile')
            
        selected_questions = sample(all_questions, 10)
        
        questions = []
        for q in selected_questions:
            questions.append({
                'id': q.id,
                'question': q.question,
                'options': {
                    'a': q.option_a,
                    'b': q.option_b,
                    'c': q.option_c,
                    'd': q.option_d
                }
            })
        
        start_time = datetime.utcnow().timestamp()
        return render_template('quiz.html', 
                             questions=questions, 
                             start_time=start_time, 
                             quiz_completed=False)
    except Exception as e:
        flash(f"Error loading quiz: {str(e)}", 'error')
        return redirect('/profile')

@app.route('/submit_quiz', methods=['POST'])
@login_required
def submit_quiz():
    try:
        start_time = float(request.form.get('start_time', 0))
        current_time = datetime.utcnow().timestamp()
        time_taken = int(current_time - start_time)

        if time_taken > 900:  # 15 minutes = 900 seconds
            flash("Time limit exceeded", 'error')
            return render_template('quiz.html', 
                                 quiz_completed=True, 
                                 score=0)

        submitted_answers = {}
        for key, value in request.form.items():
            if key.startswith('q'):
                try:
                    
                    question_num = int(key[1:])
                    submitted_answers[question_num] = value
                except ValueError:
                    continue

        score = 0
        total_questions = len([k for k in request.form.keys() if k.startswith('q')])
        
        for question_num, answer in submitted_answers.items():
            question = QuizQuestion.query.get(question_num)
            if question and answer == question.correct_answer:
                score += 1

        # Determine the performance message based on score
        if score >= 8:
            performance_message = "Excellent! You have a strong grasp of stock market concepts!"
            performance_class = "excellent"
        elif score >= 6:
            performance_message = "Good job! Keep learning and practicing!"
            performance_class = "good"
        elif score >= 4:
            performance_message = "Fair attempt! Review the material and try again."
            performance_class = "fair"
        else:
            performance_message = "Keep studying! Consider reviewing the course material."
            performance_class = "needs-improvement"

        # Calculate time taken in minutes and seconds
        minutes = time_taken // 60
        seconds = time_taken % 60
        time_message = f"{minutes} minutes and {seconds} seconds"

        return render_template('quiz.html', 
                             quiz_completed=True, 
                             score=score,
                             total_questions=total_questions,
                             performance_message=performance_message,
                             performance_class=performance_class,
                             time_taken=time_message)
    except Exception as e:
        flash(f"Error submitting quiz: {str(e)}", 'error')
        return redirect('/quiz')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect('/login')

def populate_quiz_questions():
    """Populate the database with quiz questions."""
    questions = [
        {
            "question": "Which type of trading involves buying and selling stocks within the same day?",
            "option_a": "Day trading",
            "option_b": "Swing trading",
            "option_c": "Position trading",
            "option_d": "Scalping",
            "correct_answer": "a"
        },
        {
            "question": "What is the term for buying stocks in hopes of long-term price appreciation?",
            "option_a": "Swing trading",
            "option_b": "Scalping",
            "option_c": "Investing",
            "option_d": "Short selling",
            "correct_answer": "c"
        },
        {
            "question": "In 2006, Apple's stock traded at approximately $70. If you thought the company had a future in tech, would you buy or avoid it?",
            "option_a": "Buy",
            "option_b": "Avoid",
            "option_c": "Monitor for a month",
            "option_d": "Wait for a lower price",
            "correct_answer": "a"
        },
        {
            "question": "Which trading strategy focuses on capturing short-term price movements over days or weeks?",
            "option_a": "Swing trading",
            "option_b": "Position trading",
            "option_c": "Day trading",
            "option_d": "Dividend investing",
            "correct_answer": "a"
        },
        {
            "question": "Which financial body regulates stock trading in India?",
            "option_a": "NSE",
            "option_b": "SEBI",
            "option_c": "RBI",
            "option_d": "BSE",
            "correct_answer": "b"
        },
        {
            "question": "What happens during a 'market correction'?",
            "option_a": "Stocks rise by 10%",
            "option_b": "Stocks fall by 10%",
            "option_c": "Market closes early",
            "option_d": "Trading is halted",
            "correct_answer": "b"
        },
        {
            "question": "Which strategy would a trader likely use to make many trades within minutes to seconds?",
            "option_a": "Day trading",
            "option_b": "Position trading",
            "option_c": "Swing trading",
            "option_d": "Scalping",
            "correct_answer": "d"
        },
        {
            "question": "What is a 'blue-chip' stock?",
            "option_a": "New technology stock",
            "option_b": "Penny stock",
            "option_c": "Well-established, financially sound company",
            "option_d": "High-risk startup stock",
            "correct_answer": "c"
        },
        {
            "question": "If a trader sells a stock expecting its price to decline, what is this strategy called?",
            "option_a": "Swing trading",
            "option_b": "Position trading",
            "option_c": "Scalping",
            "option_d": "Short selling",
            "correct_answer": "d"
        },
        {
            "question": "The 'bull market' refers to:",
            "option_a": "Falling prices",
            "option_b": "Rising prices",
            "option_c": "Steady prices",
            "option_d": "Short-term price movement",
            "correct_answer": "b"
        },
        {
            "question": "What is meant by 'market volatility'?",
            "option_a": "Steady price movement",
            "option_b": "Rapid price fluctuations",
            "option_c": "Market closure",
            "option_d": "Trading volume",
            "correct_answer": "b"
        },
        {
            "question": "Which trading strategy involves holding stocks for months to years?",
            "option_a": "Day trading",
            "option_b": "Swing trading",
            "option_c": "Position trading",
            "option_d": "Scalping",
            "correct_answer": "c"
        },
        {
            "question": "What is a stock split?",
            "option_a": "Company divides existing shares",
            "option_b": "Company merges shares",
            "option_c": "Stock price doubles",
            "option_d": "Company goes private",
            "correct_answer": "a"
        },
        {
            "question": "Which of the following is NOT a primary reason people trade stocks?",
            "option_a": "Price appreciation",
            "option_b": "Dividend income",
            "option_c": "Fixed returns",
            "option_d": "Portfolio diversification",
            "correct_answer": "c"
        },
        {
            "question": "What is market capitalization?",
            "option_a": "Total trading volume",
            "option_b": "Company's total share value",
            "option_c": "Daily price change",
            "option_d": "Number of shareholders",
            "correct_answer": "b"
        },
        {
            "question": "What is the primary purpose of a stock exchange?",
            "option_a": "Store stocks",
            "option_b": "Print shares",
            "option_c": "Facilitate trading",
            "option_d": "Set stock prices",
            "correct_answer": "c"
        },
        {
            "question": "What does a 'bear market' indicate?",
            "option_a": "Rising prices",
            "option_b": "Falling prices",
            "option_c": "Stable prices",
            "option_d": "Volatile prices",
            "correct_answer": "b"
        },
        {
            "question": "What is a dividend?",
            "option_a": "Stock split",
            "option_b": "Company profit share",
            "option_c": "Trading fee",
            "option_d": "Market loss",
            "correct_answer": "b"
        },
        {
            "question": "What is the meaning of 'portfolio diversification'?",
            "option_a": "Buying one stock",
            "option_b": "Spreading investments",
            "option_c": "Daily trading",
            "option_d": "Selling all stocks",
            "correct_answer": "b"
        },
        {
            "question": "Which type of order guarantees execution at market price?",
            "option_a": "Limit order",
            "option_b": "Stop order",
            "option_c": "Market order",
            "option_d": "Good-till-cancelled order",
            "correct_answer": "c"
        }
    ]
    
    try:
        for q in questions:
            existing_question = QuizQuestion.query.filter_by(question=q['question']).first()
            if not existing_question:
                new_question = QuizQuestion(
                    question=q["question"],
                    option_a=q["option_a"],
                    option_b=q["option_b"],
                    option_c=q["option_c"],
                    option_d=q["option_d"],
                    correct_answer=q["correct_answer"]
                )
                db.session.add(new_question)
        db.session.commit()
        print("Quiz questions populated successfully")
    except Exception as e:
        db.session.rollback()
        print(f"Error populating quiz questions: {str(e)}")

def init_db():
    """Initialize the database with tables and initial data."""
    try:
        with app.app_context():
            db.create_all()
            populate_quiz_questions()
            print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True, host='0.0.0.0', port=5000)