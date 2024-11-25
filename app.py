from flask import Flask, request, jsonify, render_template
import mysql.connector

app = Flask(__name__)

# MySQL Database connection
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "TypeInAPassword",
    "database": "ClassicModels"
}

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
def compare():
    data = request.get_json()
    user_query = data.get('query', '')
    reference_query = data.get('reference_query', '')
    
    # Compare the queries
    comparison = compare_individual_queries(user_query, reference_query)
    
    return jsonify(comparison)
  
@app.route('/get_questions', methods=['POST'])
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




if __name__ == '__main__':
    app.run(debug=True)