from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from dotenv import load_dotenv
import os
import json
#from models import User
from datetime import timedelta
load_dotenv()




app = Flask(__name__)

# MySQL Database connection
db_config = {
    "host": os.getenv('DBHOST'),
    "user": os.getenv('DBUSER'),
    "password": os.getenv('DBPASS'),
    "database": os.getenv('DBNAME')
}

app.config.update(
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY'),
    SESSION_COOKIE_SECURE=False,  # Set to True if using HTTPS
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60),
    REMEMBER_COOKIE_DURATION=timedelta(days=14),
    REMEMBER_COOKIE_SECURE=False,  # Set to True if using HTTPS
    REMEMBER_COOKIE_HTTPONLY=True
)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except mysql.connector.Error as e:
        print(f"Database connection error: {e}")
        return None

def init_db():
    try:
        conn = get_db_connection()
        if not conn:
            print("Could not initialize database")
            return
            
        cursor = conn.cursor()
        
        # Create users table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password_hash VARCHAR(256) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        
    except mysql.connector.Error as e:
        print(f"Database initialization error: {e}")
    finally:
        if 'cursor' in locals():
            cursor.close()
        if 'conn' in locals():
            conn.close()



# Call this when your app starts
init_db()



@login_manager.user_loader
def load_user(user_id):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if user_data:
        return User(
            id=user_data['id'],
            username=user_data['username'],
            password_hash=user_data['password_hash']
        )
    return None




def execute_query(query):
    #Executes the SQL query and returns the result.
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(query)
        result = cursor.fetchall()
    except Exception as e:
        result = {"error": str(e)}
    finally:
        cursor.close()
        conn.close()
    return result

def read_files_from_directory(directory):
    import os
    files = os.listdir(directory)
    return [file for file in files if file.lower().endswith('.sql') and os.path.isfile(os.path.join(directory, file))]


def validate_queries_json(queries_dict):
    """Validate the structure of the queries JSON."""
    if not isinstance(queries_dict, dict):
        return False
    
    for key, value in queries_dict.items():
        # Check if key can be converted to an integer
        try:
            int(key)
        except ValueError:
            return False
        
        # Check if value is a string and not empty
        if not isinstance(value, str) or not value.strip():
            return False
    
    return True

def read_values_from_file(filename):
    import os
    import json
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    try:
        with open(file_path, 'r') as file:
            queries_dict = json.load(file)
            
            if not validate_queries_json(queries_dict):
                raise ValueError("Invalid JSON structure for queries")
                
            # Sort by query number
            sorted_items = sorted(queries_dict.items(), key=lambda x: int(x[0]))
            return [(f"Query {key}", value) for key, value in sorted_items]
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []


def normalize_query(query):
    import re
    # Convert to lowercase
    query = query.lower()
    # Remove extra whitespace
    query = ' '.join(query.split())
    # Remove comments
    query = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
    query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
    # Standardize comparison operators
    query = query.replace('<>', '!=')
    return query

def compare_individual_queries(user_query, ref_query):
    # Text comparison
    query_analysis = compare_query_text(user_query, ref_query)
    
    # Execute queries and compare results
    try:
        user_result = execute_query(user_query)
        ref_result = execute_query(ref_query)
        
        result_comparison = compare_query_results(user_result, ref_result)
        
        return {
            'status': 'Compared',
            'query_analysis': query_analysis,
            'result_comparison': result_comparison
        }
    except Exception as e:
        return {
            'status': 'Error',
            'error': str(e),
            'query_analysis': query_analysis,
            'result_comparison': None
        }

def compare_query_text(user_q, ref_q):
    import difflib
    
    # Normalize queries
    norm_user = normalize_query(user_q)
    norm_ref = normalize_query(ref_q)
    
    # Get differences
    differ = difflib.Differ()
    diff = list(differ.compare(norm_user.split(), norm_ref.split()))
    
    return {
        'missing_terms': [d[2:] for d in diff if d.startswith('+ ')],
        'additional_terms': [d[2:] for d in diff if d.startswith('- ')],
        'exact_match': norm_user == norm_ref
    }

def compare_query_results(user_result, ref_result):
    if isinstance(user_result, dict) and "error" in user_result:
        return {"status": "Error", "error": user_result["error"]}
    
    if isinstance(ref_result, dict) and "error" in ref_result:
        return {"status": "Error", "error": ref_result["error"]}
    
    user_columns = list(user_result[0].keys()) if user_result else []
    ref_columns = list(ref_result[0].keys()) if ref_result else []
    
    return {
        "structure_match": user_columns == ref_columns,
        "columns": {"user": user_columns, "reference": ref_columns},
        "record_counts": {"user": len(user_result), "reference": len(ref_result)},
        "exact_match": user_result == ref_result
    }


@app.route('/', methods=['GET','POST'])
@app.route('/index', methods=['GET','POST'])
@login_required
def index():
    import os
    options = read_files_from_directory(os.path.dirname(os.path.abspath(__file__)))
    queries = []  # Initialize empty queries list
    if request.method == 'POST':
        selected_file = request.form.get('selected_file')
        if selected_file:
            queries = read_values_from_file(selected_file)
    
    # Get list of JSON files for reference file selection
    sql_files = [f for f in os.listdir(os.path.dirname(os.path.abspath(__file__))) 
                 if f.endswith('.json')]
    
    questions_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'questions')
    print(f"Questions directory: {questions_dir}")
    
    question_files = [f for f in os.listdir(questions_dir) 
                     if f.endswith('.json')]
    print(f"Found question files: {question_files}")
    
    return render_template('index.html', 
                         fileList=options, 
                         queryList=queries,
                         referenceFiles=sql_files,
                         questionFiles=question_files)  # Add reference files to template


@app.route('/compare', methods=['POST'])
@login_required
def compare():
    data = request.get_json()
    user_query = data.get('query', '')
    reference_query = data.get('reference_query', '')
    
    # Compare the queries
    comparison = compare_individual_queries(user_query, reference_query)
    
    return jsonify(comparison)

@app.route('/get_questions', methods=['POST'])
@login_required
def get_questions():
    filename = request.form.get('filename')
    if not filename:
        return jsonify({'error': 'No filename provided'}), 400
    
    try:
        file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'questions', filename)
        with open(file_path, 'r') as f:
            questions = json.load(f)
            # Add logging to debug
            print(f"Loaded questions: {questions}")
        return jsonify({'questions': questions})
    except Exception as e:
        print(f"Error loading questions: {str(e)}")  # Add logging
        return jsonify({'error': str(e)}), 500


@app.route('/get_queries', methods=['POST'])
@login_required
def get_queries():
    selected_file = request.form.get('filename')
    if selected_file:
        queries = read_values_from_file(selected_file)
        return jsonify({
            'queries': [
                {'display': display_text, 'query': query} 
                for display_text, query in queries
            ]
        })
    return jsonify({'queries': []})

@app.route('/compare_files', methods=['POST'])
@login_required
def compare_files():
    if 'userFile' not in request.files:
        return jsonify({'error': 'User file is required'}), 400
    
    user_file = request.files['userFile']
    reference_filename = request.form.get('referenceFile')  # Get selected reference filename
    
    if user_file.filename == '' or not reference_filename:
        return jsonify({'error': 'Both files must be selected'}), 400
    
    try:
        # Read and parse user file
        user_queries = json.load(user_file)
        
        # Read reference file from directory
        reference_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), reference_filename)
        with open(reference_path, 'r') as f:
            reference_queries = json.load(f)
        
        # Validate both files
        if not validate_queries_json(user_queries) or not validate_queries_json(reference_queries):
            return jsonify({'error': 'Invalid file format'}), 400
        
        # Compare all queries
        comparison_results = []
        
        # Get all query numbers from both files
        all_query_numbers = sorted(set(user_queries.keys()) | set(reference_queries.keys()))
        
        for query_num in all_query_numbers:
            user_query = user_queries.get(query_num, '')
            ref_query = reference_queries.get(query_num, '')
            
            if not user_query:
                comparison_results.append({
                    'query_number': query_num,
                    'status': 'Missing in user solution',
                    'query_analysis': None,
                    'result_comparison': None
                })
                continue
                
            if not ref_query:
                comparison_results.append({
                    'query_number': query_num,
                    'status': 'Extra query in user solution',
                    'query_analysis': None,
                    'result_comparison': None
                })
                continue
            
            # Compare individual queries
            comparison = compare_individual_queries(user_query, ref_query)
            comparison['query_number'] = query_num
            comparison_results.append(comparison)
        
        return jsonify({'comparisons': comparison_results})
        
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON format'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Debug print to verify route is being hit
    print("Login route accessed")
    
    if current_user.is_authenticated:
        print("User already authenticated, redirecting to index")
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        print(f"Login attempt for username: {username}")  # Debug print
        
        user = User.get_by_username(username)
        
        if user:
            print("User found in database")  # Debug print
            if check_password_hash(user.password_hash, password):
                print("Password verified successfully")  # Debug print
                login_user(user)
                
                # Verify user was logged in
                if current_user.is_authenticated:
                    print("User authenticated successfully")
                    next_page = url_for('index')#request.args.get('next')
                    if not next_page or not next_page.startswith('/'):
                        next_page = url_for('index')
                    print(f"Redirecting to: {next_page}")  # Debug print
                    return redirect(next_page)
                else:
                    print("User authentication failed after login_user")
            else:
                print("Password verification failed")
        else:
            print("User not found in database")
        
        flash('Invalid username or password')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not password or not confirm_password:
            flash('All fields are required')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')
            
        try:
            conn = get_db_connection()
            if not conn:
                flash('Unable to connect to database')
                return render_template('register.html')
                
            cursor = conn.cursor(dictionary=True)
            
            # Check if user exists
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                print("Username already exists in database")
                flash('Username already exists')
                return render_template('register.html')
            
            # Create new user
            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (username, password_hash)
            )
            conn.commit()
            
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
            
        except mysql.connector.Error as e:
            flash(f'Registration failed: {str(e)}')
            return render_template('register.html')
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()
            
    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal Server Error'), 500

@app.errorhandler(mysql.connector.Error)
def handle_db_error(error):
    return render_template('error.html', error='Database Error'), 500

@app.before_request
def log_request_info():
    app.logger.debug('Headers: %s', request.headers)
    app.logger.debug('Body: %s', request.get_data()) 
def before_request():
    if not request.is_secure and app.env != 'development':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url)

@app.after_request
def after_request(response):
    # Log response status
    print(f"Response status: {response.status_code}")
    return response

@app.route('/debug-session')
def debug_session():
    if app.debug:
        return {
            'user': current_user.is_authenticated,
            'session': dict(session)
        }
    return 'Debugging disabled'

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def get_id(self):
        return str(self.id)  # Must return string

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    @staticmethod
    def get_by_username(username):
        try:
            conn = mysql.connector.connect(**db_config)
            if not conn:
                print("Database connection failed")
                return None
                
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user_data = cursor.fetchone()
            
            if user_data:
                print(f"User data found: {user_data}")  # Debug print
                return User(
                    id=user_data['id'],
                    username=user_data['username'],
                    password_hash=user_data['password_hash']
                )
            print("No user found with this username")
            return None
            
        except Exception as e:
            print(f"Error in get_by_username: {e}")
            return None
        finally:
            if 'cursor' in locals():
                cursor.close()
            if 'conn' in locals():
                conn.close()



if __name__ == '__main__':
    app.run(debug=True)