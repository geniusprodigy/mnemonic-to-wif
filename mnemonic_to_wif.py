#!/usr/local/bin/python3
import sys, hashlib, ecdsa, binascii, base58
from lib.keystore import from_bip39_seed
from lib.storage import WalletStorage
from lib.wallet import Standard_Wallet



arq = open('WIFprivatekeys.txt', 'w')
arq2 = open('Addresses.txt', 'w')
def _create_standard_wallet(ks):
    gap_limit = 1  # make tests run faster
    store = WalletStorage('if_this_exists_mocking_failed_648151893')
    store.put('keystore', ks.dump())
    store.put('gap_limit', gap_limit)
    w = Standard_Wallet(store)
    w.synchronize()

    return w

def test_bip39_seed_bip49_p2sh_segwit(password, seed12):

    seed_words = seed12
    ks = from_bip39_seed(seed_words, password, "m/49'/0'/0'")
    w = _create_standard_wallet(ks)
    
    address = w.get_receiving_addresses()[0]
    priv_key_broken = w.export_private_key(address, None)
    
    print('Mnemonic: ' + seed_words)
    print('Address: ' + address)
    arq2.write("%s \n" % address)

    mpk = w.get_master_public_key()
    index = w.get_address_index(address)
    
    #repairing priv_key broken
    base58_string = priv_key_broken
    #decode WIF broken to byte_array
    step_1_base_to_array_byte = base58.b58decode(base58_string)
    #convert byte_array to hex string and remove the b'' with decode for ascii
    step_2_array_byte_to_hex = binascii.hexlify(bytearray(step_1_base_to_array_byte)).decode ('ascii')
    #remove the first 1 hex element of string and add x80
    step_2_array_byte_to_hex = '80'+step_2_array_byte_to_hex[2:]
    #remove the last 4 hex elements of string, this is required for the failure of Checksum
    step_2_array_byte_to_hex_special = step_2_array_byte_to_hex[:-8]
    #now we have the hex string correctly, just start generate of WIF standard, first sha256
    first_sha256 = hashlib.sha256(binascii.unhexlify(step_2_array_byte_to_hex_special)).hexdigest()
    #second sha256
    second_sha256 = hashlib.sha256(binascii.unhexlify(first_sha256)).hexdigest()
    #get the first 4 hex elements now for add to last of string, is the new Checksum
    new_checksum = second_sha256[:-56]
    #adding the new_checksum to the standard hexadecimal string correctly with x80 of network
    hexadecimal_string_base = step_2_array_byte_to_hex_special+new_checksum
    #just now encode to base58 and is a valid WIF
    WIF = base58.b58encode(binascii.unhexlify(hexadecimal_string_base)).decode ('ascii')

    print('WIF: ' + WIF)
    print('')
    arq.write("%s \n" % WIF)
     
with open('keys_mnemonics.txt') as file:
    for line in file:
        #my code accept strings of all types of mnemoics, i.e (seeds of 3, 6, 9, 12, 15, 18, 21, 24)
        #too is compatible of different types of Derivation Path, you can change it, using now the m/49'/0'/0'
        password=''
        seed_words = str.strip(line)
        test_bip39_seed_bip49_p2sh_segwit(password, seed_words)

print('_________________________________')
print('Developed by @genius360')
print('My contact on reddit: reddit.com/u/genius360')
print('If this help you, give me a tip please. BTC: 3FQfaUoie5Q1gHe9ye3zumobCMxJNPxrEk')