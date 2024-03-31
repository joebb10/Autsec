import re

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}})

def check_vulnerability(contract_code):
    # Check for the "unchecked-send" vulnerability
    pattern = r"call.value\((.+)\)|(\.transfer\(|\.send\()(?!require\()(?!assert\()|(msg.value|tx.value)(?!require\()(?!assert\()|(call.value\()(?!require\()(?!assert\()"
    match = re.search(pattern, contract_code)
    if match:
        line_number = contract_code.count('\n', 0, match.start()) + 1
        location = f"Line {line_number}: {match.group()}"
        unchecked_send = "Vulnerability found: unchecked-send.\n Location: " + location +   "\n. "" Explanation: This code is vulnerable to the unchecked-send vulnerability because it allows for the transfer of value without proper checks.This can result in the loss of funds for the contract's users and can be exploited by attackers.To fix this issue, ensure that the transfer of value is properly guarded by using a require() or assert() statement to check for sufficient balance or other conditions before the transfer."
    else:
        unchecked_send = "No unchecked-send vulnerability found."
  
    # Check for the "uninitialized-storage-pointer" vulnerability
    pattern = r"storage\[(.+)\] ="
    match = re.search(pattern, contract_code)
    if match:
        line_number = contract_code.count('\n', 0, match.start()) + 1
        location = f"Line {line_number}: {match.group()}"

        storage = "Vulnerability found: uninitialized-storage-pointer.\n Location: " + location +   "\n. ""Explanation: This vulnerability can occur when a storage pointer is not initialized before being used. It can lead to unauthorized access to storage data. Potential impacts include unauthorized access to sensitive data, unauthorized modification of data and financial loss."
    else:
        storage = "No uninitialized-storage-pointer vulnerability found."

      # Check for the "integer-overflow" vulnerability
    pattern = r"(\w+)\s*=\s*(\w+)\s*\+\s*(\w+)"
    match = re.search(pattern, contract_code)
    if match:
        line_number = contract_code.count('\n', 0, match.start()) + 1
        location = f"Line {line_number}: {match.group()}"
        integer_overflow = "Vulnerability found: integer-overflow \n Location: " + location +   "\n. ""Explanation: This vulnerability occurs when an integer value exceeds the maximum value that can be represented by its data type, resulting in unexpected behavior. Potential impacts include incorrect computation, unexpected behavior, and financial loss."
    else:
        integer_overflow = "No integer-overflow vulnerability found."
        
    # Check for the "reentrancy" vulnerability
    pattern = r"(call|transfer|send)\s*\(.*(msg.sender|tx.origin).*\)|address\s*payable\s*\w+\s*\=\s*msg.sender"
    match = re.search(pattern, contract_code)
    if match:
        line_number = contract_code.count('\n', 0, match.start()) + 1
        location = f"Line {line_number}: {match.group()}"
        reentrancy = "Vulnerability found: reentrancy.\n Location: " + location +   "\n. ""Explanation: This vulnerability can occur when a smart contract calls an external contract that can call the smart contract back, potentially leading to unexpected behavior. Potential impacts include unauthorized access to funds, and unexpected behavior."
    else:
        reentrancy = "No reentrancy vulnerability found."

        
    # Check for the "controlled delegate call" vulnerability
    pattern = r"delegatecall\s*\("
    match = re.search(pattern, contract_code)
    if match:
        line_number = contract_code.count('\n', 0, match.start()) + 1
        location = f"Line {line_number}: {match.group()}"
        controlled_delegate_call = "Vulnerability found: controlled delegate call.\n Location: " + location +   "\n. ""Explanation: This vulnerability occurs when a smart contract uses a delegatecall to execute an untrusted contract's code. It can lead to unauthorized access to storage data and other unexpected behavior. Potential impacts include unauthorized access to sensitive data, unauthorized modification of data and financial loss."
    else:
        controlled_delegate_call = "No controlled delegate call vulnerability found."
        
    # Check for the "oracle" vulnerability
    pattern = r"address\s*oraclizeAPI"
    match = re.search(pattern, contract_code)
    if match:
        line_number = contract_code.count('\n', 0, match.start()) + 1
        location = f"Line {line_number}: {match.group()}"
        oracle = "Vulnerability found: oracle.\n Location: " + location +   "\n. ""Explanation: This vulnerability occurs when a smart contract relies on an oracle service to provide it with external data. Potential impacts include unexpected behavior, financial loss, and unauthorized access to sensitive data."
    else:
        oracle = "No oracle vulnerability found."

    # Check for the "fallback function" vulnerability
    pattern = r"function\s*fallback\s*\("
    match = re.search(pattern, contract_code)
    if match:
      line_number = contract_code.count('\n', 0, match.start()) + 1
      location = f"Line {line_number}: {match.group()}"
      fallback = "Vulnerability found: fallback function.\n Location: " + location +   "\n Explanation: This vulnerability occurs when a smart contract uses a fallback function that is not properly guarded. It can lead to unexpected behavior and potential financial loss. Potential impacts include incorrect computation, unauthorized access to sensitive data, and financial loss."
    else:
       fallback = "No fallback function vulnerability found."
    

    
    return unchecked_send, storage, integer_overflow, reentrancy, controlled_delegate_call, oracle, fallback 


@app.route('/check_vulnerability', methods=['POST'])
def check_vuln():
    content = request.get_json()

    if 'contract_code' in content:
        contract_code = content['contract_code']
        results = check_vulnerability(str(contract_code))
        return jsonify({"unchecked_send": results[0],
                        "uninitialized_storage_pointer": results[1],
                        "integer_overflow": results[2],
                        "reentrancy": results[3],
                        "controlled_delegate_call": results[4],
                        "oracle": results[5],
                        "fallback": results[6]})
    return jsonify("You didn't send contract code on body..")
if __name__ == '__main__':
    app.run(debug=True)
