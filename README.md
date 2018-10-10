# mnemonic-to-wif
Converts many mnemonic seeds to WIF at once

# INSTALLATION - Windows

* Install Python 3+

* Install the Python PIP feature

* Download the github project folder and save where you prefer. Access the directory via Command Prompt (cmd) and install the requirements.txt file libraries, use the command for greater agility: pip install -r requirements.txt

* Create a .txt file named "keys_mnemonics.txt" and replace the directory sample file. Or edit the existing file with your mnemonics, 1 full sentence per line.

* You can now run the code with: python.exe mnemonic_to_wif.py



# INSTALLATION - Linux - Ubuntu 16.04 LTS

* Install Python3 if you have not installed it. Command: sudo apt-get install python3

* Install pip3 if you have not installed it. Command: sudo apt-get install python3-pip

* Download the github project folder and save where you prefer. Access the directory via Terminal / Shell and install the requirements.txt file libraries, use the command for greater agility: pip3 install -r requirements.txt

* Create a .txt file named "keys_mnemonics.txt" and replace the directory sample file. Or edit the existing file with your mnemonics, 1 full sentence per line.

* You can now run the code with: python3 mnemonic_to_wif.py


# SOLVING PROBLEMS

* If you still have a library missing from your system and can not install through PIP, you can separately search the dependencies reported in Terminal / Prompt and install them manually.

* For Ubuntu, you can use the command:
sudo apt install python-base58
sudo apt install python-ecdsa
sudo apt install python-base58

#RESULTS

The code will generate 2 output files:
Addresses.txt: respective addresses generated by each mnemonic line
WIFprivatekeys.txt: Private Keys in the formed Unconfigured WIF to each mnemonic line.

When opening the file with a text editor that allows you to count the lines, you can find each address and its respective WIF by the line number (010 Editor recommend)

#It could export everything into one text file, but this would end up with the chance to quickly import multiple WIF keys at once into one wallet. Since we would have both WIF and concatenated addresses.


If you need any support, just contact me. Reddit: https://www.reddit.com/user/genius360 Email: geniusprodigy@protonmail.com

If this helped you, please leave a tip. BTC: 3FQfaUoie5Q1gHe9ye3zumobCMxJNPxrEk