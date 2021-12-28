
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

'''
Metodi generali di utilità che vengono invocati negli altri files.
'''


# Effettua la codifica a chiave simmetrica dello schema di Fernet
# prende in input il plaintext e
# restituisce in output il cyphertext e la chiave utilizzata
def simm_enc(message):
    key = Fernet.generate_key()
    f = Fernet(key)
    c = f.encrypt(message)
    return key,c


# Effettua la decodifica a chiave simmetrica dello schema di Fernet
# prende in input la chiave e il cyphertext
# restituisce in output il plaintext
def simm_dec(key,c):
    f = Fernet(key)
    return f.decrypt(c)


# Calcola e restituisce la funzione di hash sha256 versione 3 per il messaggio passato in input
def sha256(m):
    h = hashes.Hash(hashes.SHA256(), backend=default_backend())
    h.update(m)
    return h.finalize()


