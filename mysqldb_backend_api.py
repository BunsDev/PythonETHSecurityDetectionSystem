from flask import Flask, request, jsonify
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)

# Configure database connection
connection = mysql.connector.connect(host='127.0.0.1',
                                     database='blockchain_security_detection_system',
                                     port=3306,
                                     user='kenneth8',
                                     password='Kena108806#')

@app.route('/analyze', methods=['POST'])
def analyze_contract():
    data = request.json
    # Here you would call the function analyze_smart_contract
    # result = analyze_smart_contract(data['code'], data['version'])
    # For now, let's assume 'result' is the response from your OpenAI call
    result = data['result']  # Replace with actual analysis result
    save_analysis_result(result)
    return jsonify(result), 200

def save_analysis_result(result):
    try:
        if connection.is_connected():
            cursor = connection.cursor()
            for vulnerability in result['Vulnerabilities']:
                cursor.execute("""
                INSERT INTO analysis_results (solidity_version, smart_contract_code, vulnerability_type, security_level, location, consequences, recommendation, explanation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    result['solidity_version'],
                    result['smart_contract_code'],
                    vulnerability['Type'],
                    vulnerability['Level'],
                    vulnerability['Location'],
                    vulnerability['Consequences'],
                    vulnerability['Recommendation'],
                    vulnerability['Explanation']
                ))
            connection.commit()
    except Error as e:
        print("Error while connecting to MySQL", e)

if __name__ == '__main__':
    app.run(debug=True)
