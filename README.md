# Phishing-Certificate-Analyzer

For editors: go into the code space ,improved orbit and copy the code into VS 
and you should see the same readme as below, as well as analyzer.py (main file) and test_analyzer.py (test file)

Requirements
- Python 3 with pip and the venv module. Use the Python installation you used to develop the project; we have not established a minimum supported version.
- The analyzer.py file.
- The packages cryptography, requests, idna, tldextract, and rich.
- For tests: pytest and test_analyzer.py.
Python includes argparse, ipaddress, socket, ssl, datetime, and urllib.parse.

Open Command Prompt and run:

python --version
python -m pip --version

make a directory for the files, mine is 

cd /d "C:\Users\keegan\Documents\PhishCert"

Then you will need to create and activate a VE(virtual Envirment) using the commands in command prompt:

python -m venv .venv
.venv\Scripts\activate.bat

you should see (.venv) before the directory this means you are ready. 

Then install depenencies:
python -m pip install cryptography requests idna tldextract rich


For the test run:
python -m pip install pytest

To actually use the anayzer run the command: 
python analyzer.py example.com

Then if you close it and want to reopen use command:

.venv\Scripts\activate.bat
python analyzer.py example.com

you can leave the VE with the command: deactivate

To run the test run the command: 

python -m pytest test_analyzer.py -v
