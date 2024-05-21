from flask import Flask, jsonify, request
from openai_chatgpt_fraud_detection_api_call import analyze_with_chatgpt as analyze_fraud
from openai_chatgpt_smartContract_vuln_detect_api_call import analyze_smart_contract
from flask_mysqldb import MySQL
from MySQLdb import cursors
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS, cross_origin
import re
import logging

app = Flask(__name__)
CORS(app)


app.config['MYSQL_HOST'] = '127.0.0.1'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_USER'] = 'amy'
app.config['MYSQL_PASSWORD'] = 'amy'
app.config['MYSQL_DB'] = 'db1'

mysql = MySQL(app)

# Clean unnecessary symbol of the result
def clean_text(text):
    # Remove leading and trailing hyphens and whitespaces
    return re.sub(r'^-\s*', '', text, flags=re.MULTILINE).strip()


###########################################################################################
#####################          User Creation and Login            ######################### 
###########################################################################################

## User Registration
@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    password = request.json['password']
    email = request.json['email']
    
    # Hash the password before storing it in the database
    hashed_password = generate_password_hash(password, method='scrypt', salt_length=8)
    
    cursor = mysql.connection.cursor()
    cursor.execute('INSERT INTO users (username, user_password, email) VALUES (%s, %s, %s)', (username, hashed_password, email))
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({'message': 'User created successfully'}), 201


## User Login
@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    
    # Create a dictionary cursor
    cursor = mysql.connection.cursor(cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    cursor.close()
    
    if user and check_password_hash(user['user_password'], password):
        # User is authenticated, proceed to log them in
        return jsonify({
            'message': 'Logged in successfully', 
            'username': user['username'], 
            'id': user['id'], 
            'email': user['email'],
            }), 200
    else:
        return jsonify({'message': 'Invalid username or password'}), 401



###########################################################################################
#####################          Smart Contract Analysis            ######################### 
###########################################################################################

## Smart contract Vulnerability Detection
@app.route('/detect_vulnerability', methods=['POST'])
def detect_vulnerability():
    data = request.json
    smart_contract_code = data.get('code', '')
    solidity_version = data.get('version', '')
    
    # Analyze the smart contract
    result = analyze_smart_contract(smart_contract_code, solidity_version)
    
    # Check if the result contains "Vulnerabilities" directly
    if 'Vulnerabilities' in result:
        # No need to extract 'vulnerability_analysis' as the result is directly the expected structure
        return jsonify(result), 200
    else:
        return jsonify({'error': 'Failed to analyze the smart contract'}), 500


# Save smart contract analysis result
@app.route('/saveContract', methods=['POST'])
def save_contract():
    data = request.json
    user_id = data.get('user_id')
    contract_name = data.get('name')
    solidity_version = data.get('version')
    smart_contract_code = data.get('code')
    vulnerabilities = data.get('vulnerabilities', [])  # This should be an array of vulnerabilities

    try:
        cursor = mysql.connection.cursor()
        for vulnerability in vulnerabilities:
            vulnerability_type = clean_text(vulnerability.get('Type', ''))
            security_level = clean_text(vulnerability.get('Level', ''))
            location = clean_text(vulnerability.get('Location', ''))
            consequences = clean_text(vulnerability.get('Consequences', ''))
            recommendation = clean_text(vulnerability.get('Recommendation', ''))
            explanation = clean_text(vulnerability.get('Explanation', ''))

            insert_query = '''
                INSERT INTO smart_contract_analysis_results
                (user_id, contract_name, solidity_version, smart_contract_code, vulnerability_type,
                security_level, location, consequences, recommendation, explanation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            '''
            cursor.execute(insert_query, (
                user_id, contract_name, solidity_version, smart_contract_code, vulnerability_type,
                security_level, location, consequences, recommendation, explanation
            ))

        mysql.connection.commit()
        cursor.close()
        return jsonify({'message': 'Smart contract analysis results saved successfully'}), 200
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': 'Failed to save the smart contract analysis results'}), 500


# Get all saved smart contract analysis history associate login used id
@app.route('/analysisHistory/<int:user_id>', methods=['GET'])
def get_analysis_history(user_id):
    # Fetch and return analysis history from the database for the given user_id
    cursor = mysql.connection.cursor(cursors.DictCursor)
    cursor.execute("SELECT * FROM smart_contract_analysis_results WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
    rows = cursor.fetchall()
    cursor.close()
    return jsonify(rows)


#search saved smart contract analysis result by search criteria
@app.route('/searchAnalysis', methods=['GET'])
def search_analysis():
    user_id = request.args.get('userId')
    name = "%" + request.args.get('name', '') + "%"
    type = "%" + request.args.get('type', '') + "%"
    date = request.args.get('date', '')
    print(f"user_id: {user_id}, name: {name}, type: {type}, date: {date}")

    cursor = mysql.connection.cursor(cursors.DictCursor)
    base_query = """
        SELECT * FROM smart_contract_analysis_results 
        WHERE user_id = %s AND 
        contract_name LIKE %s AND 
        vulnerability_type LIKE %s
    """
    query_params = [user_id, name, type]

    if date:
        base_query += " AND DATE(created_at) = STR_TO_DATE(%s, '%%Y-%%m-%%d')"  # Use the correct date format
        query_params.append(date)

    cursor.execute(base_query, query_params)
    results = cursor.fetchall()
    cursor.close()
    return jsonify(results)



#Update edited smart contract analysis result to DB
@app.route('/updateContract/<int:contract_id>', methods=['PUT'])
def update_contract(contract_id):
    data = request.json
    # Extract fields from data and update the smart_contract_analysis_results entry
    # with the matching contract_id. Here is a basic structure, add all fields necessary.

    try:
        cursor = mysql.connection.cursor()
        update_query = """
            UPDATE smart_contract_analysis_results
            SET contract_name = %s, 
                vulnerability_type = %s, 
                security_level = %s,
                location = %s, 
                consequences = %s, 
                recommendation = %s, 
                explanation = %s
            WHERE id = %s
        """
        cursor.execute(update_query, (
            data['contract_name'],
            data['vulnerability_type'],
            data['security_level'],
            data['location'],
            data['consequences'],
            data['recommendation'],
            data['explanation'],
            contract_id
        ))
        mysql.connection.commit()
        cursor.close()
        return jsonify({'message': 'Smart contract analysis result updated successfully'}), 200
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': 'Failed to update the smart contract analysis result'}), 500


#Delete smart contract analysis result in DB
@app.route('/deleteContract/<int:contract_id>', methods=['DELETE'])
def delete_contract(contract_id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM smart_contract_analysis_results WHERE id = %s", (contract_id,))
        mysql.connection.commit()
        cursor.close()
        return jsonify({'message': 'Smart contract analysis result deleted successfully'}), 200
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': 'Failed to delete the smart contract analysis result'}), 500
    

###########################################################################################
#####################          Fraud Transaction Analysis            ######################### 
###########################################################################################

## Fraud Detection
@app.route('/detect_fraud', methods=['POST'])
def detect_fraud():
    try:
        data = request.json
        transaction_hash = data.get('hash', '')
        result = analyze_fraud(transaction_hash)
        return jsonify({'fraud_analysis': result})
    except KeyError as e:
        print(f"KeyError: {e}")
        return jsonify({'error': f"An expected key is missing in the response: {e}"}), 500
    except Exception as e:
        print(f"Unexpected error: {e}")
        return jsonify({'error': 'An unexpected error occurred'}), 500


# Search fraud analysis result
@app.route('/searchFraudAnalysis', methods=['GET'])
def search_fraud_analysis():
    # Retrieve query parameters
    user_id = request.args.get('userId')
    transaction_name = request.args.get('transactionName', '%')
    fraud_type = request.args.get('fraudType', '%')
    ownership_from = request.args.get('ownershipFrom', '%')
    ownership_to = request.args.get('ownershipTo', '%')
    likelihood_of_fraud = request.args.get('likelihoodOfFraud', '%')

    try:
        cursor = mysql.connection.cursor(cursors.DictCursor)
        # Construct the search query with LIKE wildcards to allow partial matches
        search_query = """
            SELECT * FROM fraud_analysis_results WHERE
            user_id = %s AND
            transaction_name LIKE %s AND
            fraud_transaction_type LIKE %s AND
            ownership_from LIKE %s AND
            ownership_to LIKE %s AND
            likelihood_of_fraud LIKE %s
        """
        cursor.execute(search_query, (
            user_id,
            f"%{transaction_name}%",
            f"%{fraud_type}%",
            f"%{ownership_from}%",
            f"%{ownership_to}%",
            f"%{likelihood_of_fraud}%"
        ))
        results = cursor.fetchall()
        cursor.close()
        return jsonify(results), 200
    except Exception as e:
        print(f"An error occurred while searching: {e}")
        return jsonify({'error': 'Failed to search fraud analysis results'}), 500



# Save a new fraud analysis result
@app.route('/saveFraudAnalysis', methods=['POST'])
def save_fraud_analysis():
    data = request.json
    print("Incoming data:", data)  # Log the incoming data for debugging

    # Ensure the incoming data has the necessary keys
    required_fields = ['user_id', 'transaction_name', 'transaction_hash', 'fraud_analysis']
    fraud_analysis_required_fields = [
        'likelihoodOfFraud',  # The frontend sends this instead of Likelihood_of_Fraud_Or_Scam_In_Percentage
        'fraudTransactionType',
        'ownershipFrom',
        'ownershipTo',
        'behavior',
        'peculiarities',
        'broaderContext',
        'supportingEvidence',
        'recommendActions'
    ]

    # Check for missing fields
    for field in required_fields:
        if field not in data:
            print(f"Missing field: {field}")
            return jsonify({'error': f'Missing required field: {field}'}), 400

    fraud_analysis = data['fraud_analysis']
    for fa_field in fraud_analysis_required_fields:
        if fa_field not in fraud_analysis:
            print(f"Missing fraud_analysis field: {fa_field}")
            return jsonify({'error': f'Missing fraud_analysis field: {fa_field}'}), 400
        
    # Clean the text fields with clean_text function
    for key in ['behavior', 'peculiarities', 'broaderContext', 'supportingEvidence', 'recommendActions']:
        if key in fraud_analysis:
            fraud_analysis[key] = clean_text(fraud_analysis[key])

    try:
        cursor = mysql.connection.cursor()
        insert_query = """INSERT INTO fraud_analysis_results (
            user_id, transaction_name, transaction_hash, likelihood_of_fraud,
            fraud_transaction_type, ownership_from, ownership_to, behavior,
            peculiarities, broader_context, supporting_evidence, recommend_actions
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""

        # Adjust the keys to match the frontend payload
        cursor.execute(insert_query, (
            data['user_id'],
            data['transaction_name'],
            data['transaction_hash'],
            fraud_analysis['likelihoodOfFraud'],  # Now matches the frontend
            fraud_analysis['fraudTransactionType'],  # Now matches the frontend
            fraud_analysis['ownershipFrom'],  # Now matches the frontend
            fraud_analysis['ownershipTo'],  # Now matches the frontend
            fraud_analysis['behavior'],  # Now matches the frontend
            fraud_analysis['peculiarities'],  # Now matches the frontend
            fraud_analysis['broaderContext'],  # Now matches the frontend
            fraud_analysis['supportingEvidence'],  # Now matches the frontend
            fraud_analysis['recommendActions']  # Now matches the frontend
        ))
        mysql.connection.commit()
        cursor.close()
        return jsonify({'message': 'Fraud analysis result saved successfully'}), 200
    except Exception as e:
        print(f"An error occurred while inserting into database: {e}")
        return jsonify({'error': 'Failed to save the fraud analysis result: ' + str(e)}), 500


#Get Fraud transaction Analysis Result From DB
@app.route('/fraudAnalysisHistory/<int:user_id>', methods=['GET'])
def get_fraud_analysis_history(user_id):
    # Fetch and return analysis history from the database for the given user_id
    cursor = mysql.connection.cursor(cursors.DictCursor)
    cursor.execute("SELECT * FROM fraud_analysis_results WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
    rows = cursor.fetchall()
    cursor.close()
    return jsonify(rows)


#Delete Fraud transaction Analysis Result From DB
@app.route('/deleteFraudAnalysis/<int:fraud_analysis_id>', methods=['DELETE'])
def delete_fraud_analysis(fraud_analysis_id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM fraud_analysis_results WHERE id = %s", (fraud_analysis_id,))
        mysql.connection.commit()
        cursor.close()
        return jsonify({'message': 'Fraud analysis result deleted successfully'}), 200
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'error': 'Failed to delete the fraud analysis result'}), 500


#Update Fraud transaction Analysis Result From DB
@app.route('/updateFraudAnalysis/<int:fraud_analysis_id>', methods=['PUT'])
def update_fraud_analysis(fraud_analysis_id):
    logging.info(f"Updating fraud analysis {fraud_analysis_id}")
    app.logger.info('PUT request received on /updateFraudAnalysis/{}'.format(fraud_analysis_id))
    app.logger.info('Request data: {}'.format(request.data))
    data = request.get_json()  # Make sure to get the correct data
    try:
        cursor = mysql.connection.cursor()
        # Update query with proper column names matching the database schema
        update_query = """
            UPDATE fraud_analysis_results SET
            transaction_name = %s, 
            likelihood_of_fraud = %s,
            fraud_transaction_type = %s,
            ownership_from = %s,
            ownership_to = %s,
            behavior = %s,
            peculiarities = %s,
            broader_context = %s,
            supporting_evidence = %s,
            recommend_actions = %s
            WHERE id = %s
        """
        cursor.execute(update_query, (
            data['transaction_name'],
            data['likelihood_of_fraud'],
            data['fraud_transaction_type'],
            data['ownership_from'],
            data['ownership_to'],
            data['behavior'],
            data['peculiarities'],
            data['broader_context'],
            data['supporting_evidence'],
            data['recommend_actions'],
            fraud_analysis_id
        ))
        affected_rows = cursor.rowcount  # Check how many rows were affected
        mysql.connection.commit()
        cursor.close()
        if affected_rows == 0:
            return jsonify({'error': 'No records found or updated for ID: ' + str(fraud_analysis_id)}), 404
        return jsonify({'message': 'Fraud analysis updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to update fraud analysis result: ' + str(e)}), 500




###################################################################################################

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    app.run(debug=True, port=6000)
