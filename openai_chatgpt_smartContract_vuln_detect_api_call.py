import requests
import os
import json
import re
from dotenv import load_dotenv

# Load .env file where your API keys are stored
dotenv_path = os.path.join(os.path.dirname(__file__), '..', 'api_key.env')
load_dotenv(dotenv_path) 

# Retrieve the OPENAI_API_KEY from the environment variables
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

# Define the OpenAI API URL for ChatGPT model
OPENAI_API_URL = 'https://api.openai.com/v1/chat/completions'

def analyze_smart_contract(smart_contract_code, solidity_version):
    # The prompt for ChatGPT, asking it to analyze a Solidity smart contract
    prompt = f"""
    Here is the  Smart Contract Vulnerability Severity Levels explanation from Smart Contract Security Alliance for
    your reference:

    Level: High
    Explanation: The issue puts the vast majority of, or large numbers of, users’ sensitive information at risk, 
    or is reasonably likely to lead to catastrophic impact for client’s reputation or serious financial implications 
    for client and users.

    Level: Medium
    Explanation:The issue puts an subset of individual users’ sensitive information is at risk, exploitation would be detrimental 
    for the client’s reputation, or is reasonably likely to lead to moderate financial impact.
    
    Level: Low
    Explanation: The risk is relatively small and could not be exploited on a recurring basis or is a risk the client has indicated 
    is not important or impactful in view of the client’s business circumstances.

    Level: Informational
    Explanation: The issue does not pose an immediate threat to continued operation or usage, but is relevant for 
    security best practices, software engineering best practices, or defensive redundancy.
    
    Level: Undetermined
    Explanation: A condition noted during the audit where the impact of the condition is uncertain based upon the findings in 
    the audit

    *******************************************************************************************************************
    Please only group the vulnerability type to these 10 categories below:
    1. Reentrancy attacks
    2. Oracle manipulation
    3. Gas griefing
    4. Transaction order dependence attacks (frontrunning)
    5. Force-feeding attacks
    6. Timestamp dependence
    7. Denial of service
    8. Integer underflows and overflows
    9. Information and function exposure
    10. Others

    If the vulnerability you found cannot  be categorize in first 1 - 9 vulnerability, then please group to "others" category and 
    specify the category name in the explanation.
    ********************************************************************************************************************
    Now You are an blockchain security expert in Solidity and smart contract security. Analyze and audit the provided code 
    for any security vulnerabilities, with the following details for each identified issue.
    If the result of analysis of the smart contract is clean without any vulnerability, the response of the result only need to contain this in response:
    - **Vulnerability Security Level**: No Vulnerability
    - **Vulnerability Location**: N/A
    - **Vulnerability Type**: N/A
    - **Consequences**: N/A
    - **Recommendation**: N/A
    - **Explanation**: Briefly explain why it doesn't have apparent Vulnerability in bullet point format.

    Otherwise, please provide a structured analysis of the provided Solidity smart contract code, which is written in version 
    {solidity_version}. For each issue identified in the code:
    
    - **Vulnerability Security Level**: Identify the security level (High/Medium/Low/Informational/Undetermined) with standard of Smart Contract Security Alliance.
    - **Vulnerability Location**: Indicate the lines or sections of code.
    - **Vulnerability Type**: Describe the type of security issue.
    - **Consequences**: Explain what could happen if this issue is exploited.
    - **Recommendation**: Suggest how to mitigate the issue with improved code.
    - **Explanation**: Briefly clarify why your recommendations improve security in bullet point format.

    If there is vulnerability analysis result in this smart contract can not be categorized to one of those 5 levels which listed at the beginning, 
    then you shouldn't mention it in the audit result and the response.

    Smart contract code to analysis is:
    {smart_contract_code}

    Please ensure the response format is 100% fully stake with my instruction for you in above as your response is going to use in my detection system prototype.
    Every vulnerability in the analysis result must contain suitable security level.
    
    Please use bullet points and clear, concise language. Aim to provide actionable insights that help improve the contract's security.

    You must ensure the audit result and response 100% within 600 words and ensure the audit result need to be short, simple and precise.

    """

    data = {
        'model': 'gpt-4o',
        'messages': [
            {"role": "system", "content": prompt},
            {"role": "user", "content": "Analyze the smart contract"}
        ],
        'max_tokens': 1000,
        'temperature': 0.5
    }

    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {OPENAI_API_KEY}'
    }

    response = requests.post(OPENAI_API_URL, headers=headers, json=data)

    if response.status_code == 200:
        response_data = response.json()
        analysis_content = response_data['choices'][0]['message']['content']

        # Initialize structured_data with lists to hold multiple vulnerabilities
        structured_data = {
            "Vulnerabilities": []
        }

        print("Original Response: ", analysis_content)

        sections = re.split(r'- \*\*Vulnerability Security Level\*\*:', analysis_content)[1:]
        
        for section in sections:
            section = '- **Vulnerability Security Level**:' + section
            vulnerability_data = {}
            
            patterns = {
                "Level": r"- \*\*Vulnerability Security Level\*\*:\s*(.*?)\n",
                "Location": r"\*\*Vulnerability Location\*\*:\s*(.*?)\n",
                "Type": r"\*\*Vulnerability Type\*\*:\s*(.*?)\n",
                "Consequences": r"\*\*Consequences\*\*:\s*(.*?)\n",
                "Recommendation": r"\*\*Recommendation\*\*:\s*(.*?)\n",
                "Explanation": r"\*\*Explanation\*\*:\s*(.*?)(?=\n-\s*\*\*|$)",
            }
            
            for key, regex in patterns.items():
                match = re.search(regex, section, re.DOTALL)
                if match:
                    vulnerability_data[key] = match.group(1).strip()

            structured_data["Vulnerabilities"].append(vulnerability_data)
        
        print(json.dumps(structured_data, indent=4))
        return structured_data
    else:
        return f"Failed to get response: {response.status_code}\n{response.text}"
    

