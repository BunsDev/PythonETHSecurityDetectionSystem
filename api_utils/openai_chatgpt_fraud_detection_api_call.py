import requests
import json
import re 
import os
from dotenv import load_dotenv

# Load Etherscan and Google API keys from an environment file for security
dotenv_path = os.path.join(os.path.dirname(__file__), '..', 'api_key.env')
load_dotenv(dotenv_path) 
ETHERSCAN_API_KEY = os.getenv('ETHERSCAN_API_KEY')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
BITQUERY_API_KEY = os.getenv('BITQUERY_API_KEY')

# Define the OpenAI API URL
OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions'
BITQUERY_API_URL = 'https://graphql.bitquery.io/'


def get_latest_transactions():
    # Get the latest block number
    latest_block_url = f'https://api.etherscan.io/api?module=proxy&action=eth_blockNumber&apikey={ETHERSCAN_API_KEY}'
    response = requests.get(latest_block_url)
    latest_block = int(response.json()['result'], 16)

    # Fetch transactions from the latest block
    transactions_url = f'https://api.etherscan.io/api?module=proxy&action=eth_getBlockByNumber&tag={hex(latest_block)}&boolean=true&apikey={ETHERSCAN_API_KEY}'
    transactions_response = requests.get(transactions_url)
    transactions = transactions_response.json()['result']['transactions']
    
    return transactions

def preprocess_single_transaction(tx):
    # Example of preprocessing: Extracting only the necessary fields from the transaction
    preprocessed_tx = {
        'from': tx.get('from', ''),  # Sender's address
        'to': tx.get('to', ''),      # Receiver's address
        'value': tx.get('value', 0), # Value of the transaction
        'gas': tx.get('gas', 0),     # Gas used for the transaction
        # Add any other fields that are necessary for your analysis
    }
    # Convert numerical values from hexadecimal to decimal
    preprocessed_tx['value'] = int(preprocessed_tx['value'], 16)
    preprocessed_tx['gas'] = int(preprocessed_tx['gas'], 16)
    return preprocessed_tx

def preprocess_transactions(transactions):
    # Convert attributes, normalize, encode as needed
    processed_transactions = []
    for tx in transactions:
        processed_tx = preprocess_single_transaction(tx)
        processed_transactions.append(processed_tx)
    return processed_transactions

# Function to fetch transaction details
def fetch_transaction_details(tx_hash):
    etherscan_api_url = f"https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}&apikey={ETHERSCAN_API_KEY}"
    response = requests.get(etherscan_api_url)
    if response.status_code == 200:
        return response.json()['result']
    else:
        print("Failed to fetch transaction details")
        return {}

def fetch_additional_data(tx_hash):
    # Example function to fetch additional data about a transaction and its addresses
    transaction_details_url = f"https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}&apikey={ETHERSCAN_API_KEY}"
    tx_details_response = requests.get(transaction_details_url)
    # Replace the direct access with a safer check
    response = tx_details_response.json()
    if 'result' in response:
        tx_details = response['result']
    else:
        # Handle the absence of 'result', maybe log it or raise a custom error
        print(f"Expected 'result' key not found in response: {response}")
        return None, None, None  # Return None for all values
        

    from_address_details_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={tx_details['from']}&startblock=0&endblock=99999999&page=1&offset=10&sort=asc&apikey={ETHERSCAN_API_KEY}"
    from_address_response = requests.get(from_address_details_url)
    from_address_details = from_address_response.json()['result'] if from_address_response.status_code == 200 else []

    to_address_details_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={tx_details['to']}&startblock=0&endblock=99999999&page=1&offset=10&sort=asc&apikey={ETHERSCAN_API_KEY}"
    to_address_response = requests.get(to_address_details_url)
    to_address_details = to_address_response.json()['result'] if to_address_response.status_code == 200 else []

    return tx_details, from_address_details, to_address_details

# Fetch additional data from Bitquery
def fetch_bitquery_data(tx_hash):
    # Variables dictionary to be passed to the query
    variables = {
        "txHash": tx_hash
    }
    
    # Your GraphQL query as a string
    query = """
    query MyQuery ($txHash: String!) {
        ethereum(network: ethereum) {
            transactions(
                txHash: {is: $txHash}
            ) {
                gasValue
                gasPrice
                to {
                    address
                    annotation
                    smartContract {
                        contractType
                        currency {
                            symbol
                        }
                        protocolType
                    }
                }
                txType
                sender {
                    address
                    annotation
                    smartContract {
                        contractType
                        protocolType
                        currency {
                            name
                            symbol
                            tokenType
                            decimals
                        }
                    }
                }
                hash
                index
                maximum(of: date)
                minimum(of: date)
                nonce
            }
        }
    }
    """

    # Headers, including your API key for authorization
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': BITQUERY_API_KEY
    }

    # POST request with the query and variables
    response = requests.post(
        BITQUERY_API_URL,
        headers=headers,
        json={'query': query, 'variables': variables}
    )

    # Check the status code and return the data or an error message
    if response.status_code == 200:
        json_data = response.json()
        print(json.dumps(json_data, indent=4)) 
        if 'errors' in json_data:
            raise Exception(f"Bitquery error: {json_data['errors']}")
        # Here we are ensuring we have data and that it's a list with at least one transaction
        data = json_data.get('data', {}).get('ethereum', {}).get('transactions', [])
        if data and isinstance(data, list) and len(data) > 0:
            return data[0]  # Assuming we want the first (and should be only) transaction
        else:
            raise ValueError(f"No data found for transaction hash: {tx_hash}. Response: {json_data}")
    else:
        print(f"Failed to fetch data from Bitquery. Response: {response.text}")


# Calculate time difference between the first and last transactions (in minutes)
def fetch_time_difference_and_balance(address):
    # Get the list of transactions for the address, sorted by block number (asc for earliest)
    tx_list_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_API_KEY}"
    tx_list_response = requests.get(tx_list_url)
    tx_list = tx_list_response.json()['result']
    
    first_tx_time = int(tx_list[0]['timeStamp']) if tx_list else None
    last_tx_time = int(tx_list[-1]['timeStamp']) if tx_list else None
    time_diff_minutes = (last_tx_time - first_tx_time) / 60 if first_tx_time and last_tx_time else None

    balance_url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={ETHERSCAN_API_KEY}"
    balance_response = requests.get(balance_url)
    balance = int(balance_response.json()['result']) / 10**18 if balance_response.status_code == 200 else None
    
    return time_diff_minutes, balance


# Calculate minimum ETH value received
def fetch_min_value_received(address):
    # Assuming transactions are already fetched and sorted by timestamp in `fetch_time_difference_and_balance`
    tx_list_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_API_KEY}"
    tx_list_response = requests.get(tx_list_url)
    tx_list = tx_list_response.json()['result']
    
    min_value_received = min([int(tx['value']) for tx in tx_list]) / 10**18 if tx_list else None
    
    return min_value_received

def analyze_with_chatgpt(transaction_hash):
    tx_details, from_address_details, to_address_details = fetch_additional_data(transaction_hash)
    if tx_details is None:
        return "Failed to fetch transaction details, invalid transaction hash or API error."
    
    bitquery_data = fetch_bitquery_data(transaction_hash)
    if not tx_details or not bitquery_data:
        return "Failed to fetch transaction details."

    # Adjusted to directly access 'bitquery_data' as a dictionary
    from_address_contract_type = bitquery_data['sender']['smartContract'].get('contractType', 'Unknown')
    to_address_contract_type = bitquery_data['to']['smartContract'].get('contractType', 'Unknown')

    # Fetch new data points
    from_time_diff, from_balance = fetch_time_difference_and_balance(tx_details['from'])
    from_min_value_received = fetch_min_value_received(tx_details['from'])
    
    to_time_diff, to_balance = fetch_time_difference_and_balance(tx_details['to'])
    to_min_value_received = fetch_min_value_received(tx_details['to'])

    # Log the new data points for debugging
    print(f"From Time Difference: {from_time_diff} minutes")
    print(f"From Total Ether Balance: {from_balance} ETH")
    print(f"From Min Value Received: {from_min_value_received} ETH")

    print(f"To Time Difference: {to_time_diff} minutes")
    print(f"To Total Ether Balance: {to_balance} ETH")
    print(f"To Min Value Received: {to_min_value_received} ETH")
    

    prompt = f"""
    Assume you are an blockchain security expert in cryptocurrency fraud transaction detection and crypto scam phishing with access to multiple data sources including Etherscan, 
    blockchain analytics tools, and real-time market data. You are analyzing the Ethereum transaction with hash 
    {transaction_hash}.

    Based on the information and real-time data from Etherscan which listed to you below:

    Transaction Hash: {transaction_hash}
    From address: {tx_details['from']} (Previous transactions: {len(from_address_details)})
    To address: {tx_details['to']} (Previous transactions: {len(to_address_details)})
    Transaction Value: {int(tx_details['value'], 16) / 10**18} ETH
    Gas Used: {int(tx_details['gas'], 16)}

    Time difference between the first and last transactions for the From address: {from_time_diff if from_time_diff is not None else 'N/A'} minutes
    Total Ether balance for the From address: {from_balance if from_balance is not None else 'N/A'} ETH
    Minimum value received for the From address: {from_min_value_received if from_min_value_received is not None else 'N/A'} ETH

    Time difference between the first and last transactions for the To address: {to_time_diff if to_time_diff is not None else 'N/A'} minutes
    Total Ether balance for the To address: {to_balance if to_balance is not None else 'N/A'} ETH
    Minimum value received for the To address: {to_min_value_received if to_min_value_received is not None else 'N/A'} ETH

    Bitquery has provided the following additional data:
    From Address Contract Type: {from_address_contract_type}
    To Address Contract Type: {to_address_contract_type}

    With the data provided, assess the potential fraud risk of this Ethereum transaction or the from address fall in to phishing scam.

    The analysis should be structured strictly as follows, with each section's title in bold and followed by the analysis content:

    **Fraud or Phishing Risk Analysis**:
    1. **Likelihood of Fraud Or Scam In Percentage**: Only Provide a percentage estimate without explanation in this part.
    2. **Type of The Possible Fraud**: Identify and Standardize the Label of The Highest Possibility type of the fraud in these 10 listed types.
    'Financial Crimes', 'Scam Initial Coin Offerings', 'Pump and Dump Schemes', 'Market Manipulation', 'Ponzi Schemes', 'Traditional Theft', 'Broker Or Dealer Fraud', 
    'Unscrupulous Promotors', 'Unknown' or 'Other'. If the type is 'Other', please also specific the professional identification label in parentheses.

    **Address Ownership**:
    1. **Ownership of From Address**: Identify and set this as the identified name of organization, DAO, individual, group, company or if unknown. No need to provide any explanation or description.
    2. **Ownership of To Address**: Same criteria as the 'From Address'.

    **Behavior of the From and To Addresses**:
    Detail the transaction patterns and behaviors observed for both the sender and recipient addresses.

    **Peculiarities in the Transaction**:
    List and explain any peculiarities observed in the transaction, such as value anomalies or unusual gas usage.

    **Market Context and Alerts**:
    Describe the transaction's context within current market conditions and note any relevant community alerts or warnings.

    **Supporting Evidence for Assessment**:
    Provide a bullet-point list of key reasons that support your risk assessment, including any relevant patterns or indicators of fraudulent activity.

    **Recommended Actions**:
    Based on the assessment, suggest next steps or actions that could be taken.


    Keep the response within 400 words, and ensure that each section and its content are clearly distinguishable. 
    Use bold formatting for titles and normal text for content.
    Please note that the transaction can be considered as not fraud after analysis, if it is this case then the likelihood is 0% and Type of The Possible Fraud would be "No Fraud".
            
    """

    data = {
        'model': 'gpt-4-0125-preview',
        'messages': [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Analyze the transaction"}
        ],
        'max_tokens': 600,
        'temperature': 0.5
    }

    headers = {'Authorization': f'Bearer {OPENAI_API_KEY}'}
    response = requests.post(OPENAI_API_URL, headers=headers, json=data)

    if response.status_code == 200:
        response_data = response.json()
        print(response_data)
        analysis_content = response_data['choices'][0]['message']['content']
        
        # Extract structured data using regular expressions
        structured_data = {}
        patterns = {
            "Likelihood_of_Fraud_Or_Scam_In_Percentage": r"\*\*Likelihood of Fraud Or Scam In Percentage\*\*:\s*(\d+%)\s*",
            "Type_of_The_Possible_Fraud": r"\*\*Type of The Possible Fraud\*\*:\s*([^\n]+)",
            "Ownership_of_From_Address": r"\*\*Ownership of From Address\*\*:\s*(\S+)",
            "Ownership_of_To_Address": r"\*\*Ownership of To Address\*\*:\s*(.+?)(?=\*\*Behavior of the From and To Addresses\*\*)",
            "Behavior_of_the_From_and_To_Addresses": r"\*\*Behavior of the From and To Addresses\*\*:\s*(.+?)(?=\*\*Peculiarities in the Transaction\*\*)",
            "Peculiarities_in_the_Transaction": r"\*\*Peculiarities in the Transaction\*\*:\s*(.+?)(?=\*\*Market Context and Alerts\*\*)",
            "Market_Context_and_Alerts": r"\*\*Market Context and Alerts\*\*:\s*(.+?)(?=\*\*Supporting Evidence for Assessment\*\*)",
            "Supporting_Evidence_for_Assessment": r"\*\*Supporting Evidence for Assessment\*\*:\s*(.+?)(?=\*\*Recommended Actions\*\*)",
            "Recommended_Actions": r"\*\*Recommended Actions\*\*:\s*(.+)"
        }

        # Loop through each pattern and extract the corresponding data
        for key, pattern in patterns.items():
            match = re.search(pattern, analysis_content, re.DOTALL | re.IGNORECASE)
            if match:
                structured_data[key] = match.group(1).strip()
        
        return structured_data
    else:
        # Handle the case where the API call was unsuccessful
        return f"Error during API call: {response.status_code}\n{response.text}"

  
