import os
import google.generativeai as genai

# Configure the Google AI Python SDK with your Google API key
os.environ["API_KEY"] = "AIzaSyAMLUkVZiT8y6P0cexYbEUdemfSKP_Wd-M"  
genai.configure(api_key=os.environ["API_KEY"])

# Load the Gemini model
model = genai.GenerativeModel('gemini-pro')

# Solidity smart contract code
smart_contract_code = """
 pragma solidity ^0.4.15;


contract DosAuction {
  address currentFrontrunner;
  uint currentBid;


  function bid() payable {
    require(msg.value > currentBid);


    if (currentFrontrunner != 0) {

      require(currentFrontrunner.send(currentBid));
    }

    currentFrontrunner = msg.sender;
    currentBid         = msg.value;
  }
}

"""

# The prompt for Gemini, asking it to analyze a Solidity smart contract
prompt = """
I'm auditing a Solidity smart contract for security vulnerabilities, focusing on best practices, common pitfalls, 
and compatibility with the used Solidity version. Please review the code provided below. 
For each potential vulnerability or issue:
- Highlight the specific code affected.
- Describe the nature of the problem.
- Explain the possible consequences if the issue is not addressed.
- Offer recommendations for mitigation or improvement.

Your analysis will help ensure the contract is robust, secure, and free from common vulnerabilities.


Solidity Smart Contract Code:
""" + smart_contract_code


# Use the model to generate content based on the prompt
response = model.generate_content(prompt)
print("Gemini's analysis:", response.text)
