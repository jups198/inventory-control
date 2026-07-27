import os
from datetime import datetime, timezone
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

# ── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-me-in-production-!')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL', 'sqlite:///inventory.db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'


# ── Models ───────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    transactions = db.relationship('StockTransaction', backref='user', lazy=True)
    items_created = db.relationship('Item', backref='creator', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == 'admin'


class Item(db.Model):
    __tablename__ = 'items'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default='')
    sku = db.Column(db.String(100), unique=True, nullable=True)
    current_stock = db.Column(db.Integer, default=0)
    min_stock = db.Column(db.Integer, default=0)
    unit = db.Column(db.String(50), default='pcs')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    transactions = db.relationship('StockTransaction', backref='item', lazy=True,
                                   order_by='StockTransaction.created_at.desc()')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'sku': self.sku,
            'current_stock': self.current_stock,
            'min_stock': self.min_stock,
            'unit': self.unit,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
        }


class StockTransaction(db.Model):
    __tablename__ = 'stock_transactions'
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('items.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'in', 'out', 'add'
    quantity = db.Column(db.Integer, nullable=False)
    notes = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# ── Auth Setup ───────────────────────────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ── Decorators ───────────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ── Auth Routes ──────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=request.form.get('remember'))
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if not email or '@' not in email:
            errors.append('Valid email required.')
        if len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if password != confirm:
            errors.append('Passwords do not match.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html')

        # First registered user becomes admin
        is_first = User.query.count() == 0
        user = User(
            username=username,
            email=email,
            role='admin' if is_first else 'user'
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash('Account created! Welcome to Inventory Control.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


# ── Dashboard ────────────────────────────────────────────────────────────────
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    items = Item.query.order_by(Item.name).all()
    low_stock = [i for i in items if i.current_stock <= i.min_stock]
    recent_tx = StockTransaction.query.order_by(
        StockTransaction.created_at.desc()
    ).limit(20).all()
    return render_template('dashboard.html',
                           items=items, low_stock=low_stock, recent_tx=recent_tx)


# ── Item Routes ──────────────────────────────────────────────────────────────
@app.route('/items')
@login_required
def items_list():
    search = request.args.get('q', '').strip()
    if search:
        items = Item.query.filter(
            Item.name.ilike(f'%{search}%') |
            Item.sku.ilike(f'%{search}%') |
            Item.description.ilike(f'%{search}%')
        ).order_by(Item.name).all()
    else:
        items = Item.query.order_by(Item.name).all()
    return render_template('items_list.html', items=items, search=search)


@app.route('/items/add', methods=['GET', 'POST'])
@login_required
def add_item():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        if not name:
            flash('Item name is required.', 'danger')
            return render_template('add_item.html')

        sku = request.form.get('sku', '').strip() or None
        if sku and Item.query.filter_by(sku=sku).first():
            flash('SKU already exists.', 'danger')
            return render_template('add_item.html')

        initial_stock = int(request.form.get('initial_stock', 0) or 0)
        item = Item(
            name=name,
            description=request.form.get('description', '').strip(),
            sku=sku,
            current_stock=initial_stock,
            min_stock=int(request.form.get('min_stock', 0) or 0),
            unit=request.form.get('unit', 'pcs').strip(),
            created_by=current_user.id,
        )
        db.session.add(item)
        db.session.flush()

        if initial_stock > 0:
            tx = StockTransaction(
                item_id=item.id, user_id=current_user.id,
                type='add', quantity=initial_stock,
                notes='Initial stock from item creation'
            )
            db.session.add(tx)

        db.session.commit()
        flash(f'Item "{name}" added with {initial_stock} stock.', 'success')
        return redirect(url_for('items_list'))
    return render_template('add_item.html')


@app.route('/items/<int:item_id>')
@login_required
def item_detail(item_id):
    item = db.session.get(Item, item_id)
    if not item:
        abort(404)
    transactions = StockTransaction.query.filter_by(item_id=item_id)\
        .order_by(StockTransaction.created_at.desc()).all()
    return render_template('item_detail.html', item=item, transactions=transactions)


@app.route('/items/<int:item_id>/stock', methods=['POST'])
@login_required
def adjust_stock(item_id):
    item = db.session.get(Item, item_id)
    if not item:
        abort(404)

    action = request.form.get('action')  # 'increase' or 'decrease'
    quantity = int(request.form.get('quantity', 0) or 0)
    notes = request.form.get('notes', '').strip()

    if quantity <= 0:
        flash('Quantity must be positive.', 'danger')
        return redirect(url_for('item_detail', item_id=item_id))

    if action == 'increase':
        item.current_stock += quantity
        tx_type = 'in'
        msg = f'Added {quantity} {item.unit}.'
    elif action == 'decrease':
        if quantity > item.current_stock:
            flash(f'Cannot remove {quantity}: only {item.current_stock} {item.unit} available.', 'danger')
            return redirect(url_for('item_detail', item_id=item_id))
        item.current_stock -= quantity
        tx_type = 'out'
        msg = f'Removed {quantity} {item.unit}.'
    else:
        flash('Invalid action.', 'danger')
        return redirect(url_for('item_detail', item_id=item_id))

    tx = StockTransaction(
        item_id=item_id, user_id=current_user.id,
        type=tx_type, quantity=quantity, notes=notes
    )
    db.session.add(tx)
    db.session.commit()
    flash(msg + (f' Note: {notes}' if notes else ''), 'success')
    return redirect(url_for('item_detail', item_id=item_id))


# ── Admin Routes ─────────────────────────────────────────────────────────────
@app.route('/admin')
@admin_required
def admin_panel():
    users = User.query.order_by(User.created_at).all()
    items = Item.query.order_by(Item.name).all()
    return render_template('admin.html', users=users, items=items)


@app.route('/admin/users/<int:user_id>/role', methods=['POST'])
@admin_required
def change_role(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    new_role = request.form.get('role', 'user')
    if new_role not in ('user', 'admin'):
        flash('Invalid role.', 'danger')
        return redirect(url_for('admin_panel'))
    if user.id == current_user.id:
        flash('Cannot change your own role.', 'danger')
        return redirect(url_for('admin_panel'))
    user.role = new_role
    db.session.commit()
    flash(f'{user.username} is now {new_role}.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/items/<int:item_id>/delete', methods=['POST'])
@admin_required
def delete_item(item_id):
    item = db.session.get(Item, item_id)
    if not item:
        abort(404)
    # Delete all transactions first, then item
    StockTransaction.query.filter_by(item_id=item_id).delete()
    name = item.name
    db.session.delete(item)
    db.session.commit()
    flash(f'Item "{name}" and all its history permanently deleted.', 'warning')
    return redirect(url_for('items_list'))


# ── API (for potential mobile/PWA use) ───────────────────────────────────────
@app.route('/api/items')
@login_required
def api_items():
    items = Item.query.order_by(Item.name).all()
    return jsonify([i.to_dict() for i in items])


@app.route('/api/items/<int:item_id>/transactions')
@login_required
def api_transactions(item_id):
    txs = StockTransaction.query.filter_by(item_id=item_id)\
        .order_by(StockTransaction.created_at.desc()).limit(100).all()
    return jsonify([{
        'id': tx.id, 'type': tx.type, 'quantity': tx.quantity,
        'notes': tx.notes, 'user': tx.user.username,
        'created_at': tx.created_at.isoformat(),
    } for tx in txs])


# ── Error Handlers ───────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


# ── Init DB + Create Admin ───────────────────────────────────────────────────
def init_db():
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            admin = User(username='admin', email='admin@inventory.local', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('✓ Default admin created: admin / admin123')
            print('  CHANGE THE PASSWORD after first login!')


# ── Run ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
