Autsec: Smart Contract Vulnerability Checker

Autsec is a static analysis tool for auditing smart contracts, designed to identify common vulnerabilities within contract code. Utilizing regular expressions, Autsec scans contracts for patterns indicative of potential security issues such as unchecked sends, reentrancy, integer overflow, and more. Developed with a focus on Ethereum smart contracts, Autsec aims to improve security practices in the development of decentralized applications.

Features

Detects common vulnerabilities in smart contract code:
Unchecked send
Uninitialized storage pointers
Integer overflow
Reentrancy attacks
Controlled delegate call
Oracle reliance
Improper fallback function usage
Easy integration with development workflows via a RESTful API
Open-source and extensible for community-driven improvements
Installation

Autsec is built on Flask and requires Python to run. You can install Autsec and its dependencies using the following commands:


git clone https://github.com/joebb10/Autsec-.git

cd autsec-

pip install -r requirements.txt

Usage

To start the Autsec server, run:

python autsec.py
This command starts the Flask server on localhost with the default port 8080. To check a smart contract for vulnerabilities, send a POST request to the /check_vulnerability endpoint with the contract code as JSON:


curl -X POST http://localhost:8080/check_vulnerability -H "Content-Type: application/json" -d '{"contract_code":"your smart contract code here"}'
Replace "your smart contract code here" with the actual code of the smart contract you want to audit.

Example Response
The response will include details of any vulnerabilities found:

{
  "unchecked_send": "No unchecked-send vulnerability found.",
  
  "uninitialized_storage_pointer": "Vulnerability found: uninitialized-storage-pointer...",
  
  "integer_overflow": "No integer-overflow vulnerability found.",
  
  // Additional fields omitted for brevity
}

Contributing

We welcome contributions to Autsec! If you're interested in helping, you can:

Report issues or suggest new features
Submit pull requests with bug fixes or enhancements
Improve documentation or write tutorials
Please see CONTRIBUTING.md for more information on how to contribute.

License

Autsec is licensed under MIT License. Feel free to use, modify, and distribute it as per the license.

