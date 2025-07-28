import os
import boto3
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import uuid
from decimal import Decimal

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'pawsclaws_secret_key_2024')

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')

# Table Names
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'PetShopUsers')
PRODUCTS_TABLE_NAME = os.environ.get('PRODUCTS_TABLE_NAME', 'PetProducts')
ORDERS_TABLE_NAME = os.environ.get('ORDERS_TABLE_NAME', 'PetOrders')
CART_TABLE_NAME = os.environ.get('CART_TABLE_NAME', 'PetCart')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
sns = boto3.client('sns', region_name=AWS_REGION_NAME)

# DynamoDB Tables
users_table = dynamodb.Table(USERS_TABLE_NAME)
products_table = dynamodb.Table(PRODUCTS_TABLE_NAME)
orders_table = dynamodb.Table(ORDERS_TABLE_NAME)
cart_table = dynamodb.Table(CART_TABLE_NAME)

# ---------------------------------------
# Utility Functions
# ---------------------------------------
def send_sns_notification(message, subject):
    """Send SNS notification for orders and promotions"""
    if ENABLE_SNS and SNS_TOPIC_ARN:
        try:
            sns.publish(
                TopicArn=SNS_TOPIC_ARN,
                Message=message,
                Subject=subject
            )
            return True
        except Exception as e:
            print(f"SNS Error: {e}")
            return False
    return False

def login_required(f):
    """Decorator for routes that require login"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def admin_required(f):
    """Decorator for admin-only routes"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_role') != 'admin':
            flash('Admin access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def customer_required(f):
    """Decorator for customer-only routes"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('user_role') != 'customer':
            flash('Customer access required')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# ---------------------------------------
# Authentication Routes
# ---------------------------------------
@app.route('/')
def index():
    """Home page showing featured products"""
    try:
        # Get featured products
        response = products_table.scan(Limit=6)
        featured_products = response.get('Items', [])
        return render_template('index.html', products=featured_products)
    except Exception as e:
        return render_template('index.html', products=[])

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        data = request.form
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        phone = data.get('phone', '')
        address = data.get('address', '')
        role = data.get('role', 'customer')

        if not all([username, email, password]):
            flash('Username, email and password are required')
            return render_template('register.html')

        # Check if user exists
        try:
            response = users_table.get_item(Key={'email': email})
            if 'Item' in response:
                flash('User already exists')
                return render_template('register.html')
        except Exception as e:
            flash('Database error')
            return render_template('register.html')

        # Create new user
        user_id = str(uuid.uuid4())
        hashed_password = generate_password_hash(password)

        try:
            users_table.put_item(Item={
                'user_id': user_id,
                'email': email,
                'username': username,
                'password': hashed_password,
                'phone': phone,
                'address': address,
                'role': role,
                'created_at': datetime.now().isoformat(),
                'is_active': True
            })

            flash('Registration successful! Please login.')
            return redirect(url_for('login'))

        except Exception as e:
            flash('Registration failed')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        data = request.form
        
        email = data.get('email')
        password = data.get('password')
        
        if not all([email, password]):
            flash('Email and password required')
            return render_template('login.html')
        
        try:
            response = users_table.get_item(Key={'email': email})
            if 'Item' not in response:
                flash('Invalid credentials')
                return render_template('login.html')
            
            user = response['Item']
            
            if not user.get('is_active', True):
                flash('Account deactivated')
                return render_template('login.html')
            
            if check_password_hash(user['password'], password):
                session['user_id'] = user['user_id']
                session['username'] = user['username']
                session['email'] = user['email']
                session['user_role'] = user.get('role', 'customer')
                
                flash(f'Welcome back, {user["username"]}!')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials')
                return render_template('login.html')
                
        except Exception as e:
            flash('Login failed')
            return render_template('login.html')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('Logged out successfully')
    return redirect(url_for('index'))

# ---------------------------------------
# Dashboard Routes
# ---------------------------------------
@app.route('/dashboard')
@login_required
def dashboard():
    """Route users to appropriate dashboard"""
    user_role = session.get('user_role', 'customer')
    
    if user_role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('customer_dashboard'))

@app.route('/customer/dashboard')
@customer_required
def customer_dashboard():
    """Customer dashboard showing recent orders and recommendations"""
    try:
        # Get customer's recent orders
        orders_response = orders_table.query(
            IndexName='CustomerIndex',
            KeyConditionExpression='customer_id = :customer_id',
            ExpressionAttributeValues={':customer_id': session['user_id']},
            Limit=5,
            ScanIndexForward=False
        )
        recent_orders = orders_response.get('Items', [])
        
        # Get cart items count
        cart_response = cart_table.query(
            IndexName='CustomerIndex',
            KeyConditionExpression='customer_id = :customer_id',
            ExpressionAttributeValues={':customer_id': session['user_id']}
        )
        cart_items = len(cart_response.get('Items', []))
        
        # Get featured products
        products_response = products_table.scan(Limit=4)
        featured_products = products_response.get('Items', [])
        
        return render_template('customer_dashboard.html', 
                             recent_orders=recent_orders,
                             cart_items=cart_items,
                             featured_products=featured_products)
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}')
        return render_template('customer_dashboard.html', 
                             recent_orders=[], cart_items=0, featured_products=[])

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard with business metrics"""
    try:
        # Get total products
        products_response = products_table.scan()
        total_products = len(products_response.get('Items', []))
        
        # Get total orders
        orders_response = orders_table.scan()
        all_orders = orders_response.get('Items', [])
        total_orders = len(all_orders)
        
        # Calculate total revenue
        total_revenue = sum(float(order.get('total_amount', 0)) for order in all_orders)
        
        # Get recent orders
        recent_orders = sorted(all_orders, key=lambda x: x.get('created_at', ''), reverse=True)[:10]
        
        # Product categories stats
        category_stats = {}
        for product in products_response.get('Items', []):
            category = product.get('category', 'Other')
            if category not in category_stats:
                category_stats[category] = 0
            category_stats[category] += 1
        
        return render_template('admin_dashboard.html',
                             total_products=total_products,
                             total_orders=total_orders,
                             total_revenue=total_revenue,
                             recent_orders=recent_orders,
                             category_stats=category_stats)
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}')
        return render_template('admin_dashboard.html',
                             total_products=0, total_orders=0, total_revenue=0,
                             recent_orders=[], category_stats={})

# ---------------------------------------
# Product Management Routes
# ---------------------------------------
@app.route('/products')
def products():
    """View all products, optionally filtered by category"""
    try:
        # Fetch all products
        response = products_table.scan()
        products_list = response.get('Items', [])

        # Filter by category if passed in URL query
        category = request.args.get('category')
        if category:
            products_list = [product for product in products_list if product.get('category') == category]

        return render_template('products.html',
                               products=products_list,
                               selected_category=category or None)
    except Exception as e:
        error_msg = f'Error loading products: {str(e)}'
        print(error_msg)
        flash(error_msg)
        return render_template('products.html', products=[], selected_category=None)


@app.route('/product/<product_id>')
def product_details(product_id):
    """View single product details"""
    try:
        response = products_table.get_item(Key={'product_id': product_id})
        product = response.get('Item')
        
        if not product:
            flash('Product not found')
            return redirect(url_for('products'))
        
        return render_template('product_details.html', product=product)
    except Exception as e:
        flash('Error loading product')
        return redirect(url_for('products'))

@app.route('/admin/products/add', methods=['GET', 'POST'])
@admin_required
def add_product():
    """Add new product (admin only)"""
    if request.method == 'POST':
        data = request.form
        
        name = data.get('name')
        description = data.get('description')
        price = data.get('price')
        category = data.get('category')
        stock_quantity = data.get('stock_quantity')
        image_url = data.get('image_url', '')
        
        if not all([name, description, price, category, stock_quantity]):
            flash('All fields are required')
            return render_template('add_product.html')
        
        product_id = str(uuid.uuid4())
        
        try:
            products_table.put_item(Item={
                'product_id': product_id,
                'name': name,
                'description': description,
                'price': Decimal(str(price)),
                'category': category,
                'stock_quantity': int(stock_quantity),
                'image_url': image_url,
                'is_active': True,
                'created_at': datetime.now().isoformat()
            })
            
            flash('Product added successfully')
            return redirect(url_for('products'))
                
        except Exception as e:
            flash('Failed to add product')
            return render_template('add_product.html')
    
    return render_template('add_product.html')

# ---------------------------------------
# Shopping Cart Routes
# ---------------------------------------


from boto3.dynamodb.conditions import Key

@app.route('/cart')
@customer_required
def cart():
    """View shopping cart"""
    try:
        response = cart_table.query(
            KeyConditionExpression=Key('customer_id').eq(session['user_id'])
        )
        cart_items = response.get('Items', [])

        cart_with_products = []
        total_amount = 0.0

        for item in cart_items:
            product_response = products_table.get_item(Key={'product_id': item['product_id']})
            product = product_response.get('Item')

            if product:
                quantity = int(item.get('quantity', 1))
                price = float(product.get('price', 0))
                item_total = quantity * price

                cart_with_products.append({
                    'cart_item': item,
                    'product': product,
                    'item_total': item_total
                })

                total_amount += item_total

        return render_template('cart.html', cart_items=cart_with_products, total_amount=total_amount)

    except Exception as e:
        print(f"[Cart Load Error] {e}")
        flash(f'Error loading cart: {str(e)}')
        return render_template('cart.html', cart_items=[], total_amount=0.0)


@app.route('/cart/add', methods=['POST'])
@customer_required
def add_to_cart():
    """Add item to cart"""
    data = request.form
    product_id = data.get('product_id')
    quantity = int(data.get('quantity', 1))

    if not product_id:
        flash('Invalid product.')
        return redirect(url_for('products'))

    try:
        # Check if item exists
        response = cart_table.get_item(Key={
            'customer_id': session['user_id'],
            'product_id': product_id
        })

        if 'Item' in response:
            # Update quantity
            cart_table.update_item(
                Key={
                    'customer_id': session['user_id'],
                    'product_id': product_id
                },
                UpdateExpression='SET quantity = quantity + :q',
                ExpressionAttributeValues={':q': quantity}
            )
        else:
            # Add new item
            cart_table.put_item(Item={
                'customer_id': session['user_id'],
                'product_id': product_id,
                'quantity': quantity,
                'added_at': datetime.now().isoformat()
            })

        flash('Item added to cart.')
        return redirect(url_for('cart'))

    except Exception as e:
        print(f"[Cart Add Error] {e}")
        flash('Failed to add item to cart.')
        return redirect(url_for('products'))


@app.route('/cart/remove/<product_id>')
@customer_required
def remove_from_cart(product_id):
    """Remove item from cart"""
    try:
        cart_table.delete_item(Key={
            'customer_id': session['user_id'],
            'product_id': product_id
        })
        flash('Item removed from cart.')
    except Exception as e:
        print(f"[Cart Remove Error] {e}")
        flash('Failed to remove item from cart.')

    return redirect(url_for('cart'))


# ---------------------------------------
# Order Management Routes
# ---------------------------------------

from boto3.dynamodb.conditions import Key
from decimal import Decimal

def convert_decimals(obj):
    """Convert DynamoDB Decimal objects to float for JSON serialization"""
    if isinstance(obj, list):
        return [convert_decimals(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: convert_decimals(value) for key, value in obj.items()}
    elif isinstance(obj, Decimal):
        return float(obj)
    else:
        return obj

@app.route('/orders')
@customer_required
def orders():
    """View customer orders"""
    try:
        response = orders_table.query(
            IndexName='CustomerIndex',
            KeyConditionExpression=Key('customer_id').eq(session['user_id']),
            ScanIndexForward=False  # Latest orders first
        )
        customer_orders = response.get('Items', [])
        
        # Convert DynamoDB types to regular Python types
        customer_orders = convert_decimals(customer_orders)
        
        print(f"[DEBUG] Converted orders: {len(customer_orders)} orders")
        if customer_orders:
            print(f"[DEBUG] Sample converted order items: {type(customer_orders[0].get('items'))}")
        
        return render_template('orders.html', orders=customer_orders)
        
    except Exception as e:
        print(f"[Orders Error] {e}")
        import traceback
        traceback.print_exc()
        flash(f'Error loading orders: {str(e)}')
        return render_template('orders.html', orders=[])


from boto3.dynamodb.conditions import Key
from decimal import Decimal

@app.route('/checkout', methods=['GET', 'POST'])
@customer_required
def checkout():
    """Process order checkout"""
    if request.method == 'POST':
        data = request.form
        
        shipping_address = data.get('shipping_address')
        payment_method = data.get('payment_method')
        
        if not all([shipping_address, payment_method]):
            flash('All fields are required')
            return render_template('checkout.html')
        
        try:
            # Get cart items
            cart_response = cart_table.query(
                KeyConditionExpression=Key('customer_id').eq(session['user_id'])
            )
            cart_items = cart_response.get('Items', [])
            
            if not cart_items:
                flash('Cart is empty')
                return redirect(url_for('cart'))
            
            # Calculate total
            total_amount = Decimal('0')
            order_items = []
            
            for item in cart_items:
                product_response = products_table.get_item(Key={'product_id': item['product_id']})
                product = product_response.get('Item')
                if product:
                    price = Decimal(str(product['price']))
                    quantity = int(item['quantity'])
                    item_total = price * quantity
                    total_amount += item_total
                    order_items.append({
                        'product_id': item['product_id'],
                        'product_name': product['name'],
                        'quantity': quantity,
                        'price': price,
                        'total': item_total
                    })
            
            # Create order
            order_id = str(uuid.uuid4())
            orders_table.put_item(Item={
                'order_id': order_id,
                'customer_id': session['user_id'],
                'customer_name': session['username'],
                'items': order_items,
                'total_amount': total_amount,
                'shipping_address': shipping_address,
                'payment_method': payment_method,
                'status': 'pending',
                'created_at': datetime.now().isoformat()
            })
            
            # Clear cart
            for item in cart_items:
                # Cart table uses composite key (customer_id + product_id)
                cart_table.delete_item(Key={
                    'customer_id': item['customer_id'],
                    'product_id': item['product_id']
                })
            
            # Send notification
            message = f"New order received!\nOrder ID: {order_id}\nCustomer: {session['username']}\nTotal: ₹{total_amount}"
            send_sns_notification(message, "New Pet Store Order")
            
            flash('Order placed successfully!')
            return redirect(url_for('orders'))
            
        except Exception as e:
            print(f"[Checkout Error] {e}")
            flash('Failed to place order')
            # Get cart items for template in case of error
            try:
                cart_response = cart_table.query(
                    KeyConditionExpression=Key('customer_id').eq(session['user_id'])
                )
                raw_items = cart_response.get('Items', [])
                cart_items = []
                total_amount = 0
                
                for item in raw_items:
                    product_response = products_table.get_item(Key={'product_id': item['product_id']})
                    product = product_response.get('Item')
                    if product:
                        item_total = float(product['price']) * int(item['quantity'])
                        total_amount += item_total
                        cart_item = {
                            'cart_id': item.get('cart_id'),
                            'customer_id': item.get('customer_id'),
                            'product_id': item.get('product_id'),
                            'quantity': item.get('quantity'),
                            'product': product,
                            'item_total': item_total
                        }
                        cart_items.append(cart_item)
                
                return render_template('checkout.html', cart_items=cart_items, total_amount=total_amount)
            except:
                return redirect(url_for('cart'))
    
    # GET: Show checkout form
    try:
        # Get cart items with full product details
        cart_response = cart_table.query(
            KeyConditionExpression=Key('customer_id').eq(session['user_id'])
        )
        raw_items = cart_response.get('Items', [])

        cart_items = []
        total_amount = 0
        
        for item in raw_items:
            try:
                product_response = products_table.get_item(Key={'product_id': item['product_id']})
                product = product_response.get('Item')
                if product:
                    item_total = float(product['price']) * int(item['quantity'])
                    total_amount += item_total
                    
                    # Create cart item with flat structure
                    cart_item = {
                        'cart_id': item.get('cart_id'),
                        'customer_id': item.get('customer_id'),
                        'product_id': item.get('product_id'),
                        'quantity': item.get('quantity'),
                        'product': product,
                        'item_total': item_total
                    }
                    cart_items.append(cart_item)
            except Exception as item_error:
                print(f"[Cart Item Error] Error processing item {item.get('product_id', 'unknown')}: {item_error}")
                continue

        if not cart_items:
            flash('Cart is empty')
            return redirect(url_for('cart'))

        return render_template('checkout.html', cart_items=cart_items, total_amount=total_amount)

    except Exception as e:
        print(f"[Checkout Load Error] {e}")
        flash('Error loading checkout')
        return redirect(url_for('cart'))

@app.route('/admin/orders')
@admin_required
def admin_orders():
    """Admin view of all orders"""
    try:
        response = orders_table.scan()
        all_orders = response.get('Items', [])
        all_orders.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return render_template('admin_orders.html', orders=all_orders)
    except Exception as e:
        flash(f'Error loading orders: {str(e)}')
        return render_template('admin_orders.html', orders=[])

@app.route('/admin/orders/<order_id>/update', methods=['POST'])
@admin_required
def update_order_status(order_id):
    """Update order status"""
    new_status = request.form.get('status')
    
    try:
        orders_table.update_item(
            Key={'order_id': order_id},
            UpdateExpression='SET #status = :status',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':status': new_status}
        )
        
        flash('Order status updated')
    except Exception as e:
        flash('Failed to update order status')
    
    return redirect(url_for('admin_orders'))

# ---------------------------------------
# API Routes
# ---------------------------------------
@app.route('/api/products')
def api_products():
    """API endpoint for products"""
    try:
        response = products_table.scan()
        products_list = response.get('Items', [])
        
        # Convert Decimal to float for JSON serialization
        for product in products_list:
            if 'price' in product:
                product['price'] = float(product['price'])
        
        return jsonify(products_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/orders/stats')
@admin_required
def api_order_stats():
    """API endpoint for order statistics"""
    try:
        response = orders_table.scan()
        orders = response.get('Items', [])
        
        stats = {
            'total_orders': len(orders),
            'pending_orders': len([o for o in orders if o.get('status') == 'pending']),
            'completed_orders': len([o for o in orders if o.get('status') == 'completed']),
            'total_revenue': sum(float(o.get('total_amount', 0)) for o in orders)
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------------------------------------
# Error Handlers
# ---------------------------------------
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal server error'), 500

# ---------------------------------------
# Main
# ---------------------------------------
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
