
from flask import Flask
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from random import randint
import requests
from time import sleep
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import re

# Caricamento in memoria della chiave privata del laboratorio a partire dal file privato
with open("keyLab.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(),password = None,backend=default_backend())


def risultato_tampone(x, tempo=10):
    '''
    Funzione che calcola semplicemente il risultato del tampone, simulando che con probabilità
    pari al 50% esce positivo, altrimenti negativo. In caso di positività viene inviata
    la x del cittadino in questione al server del Governo.

    :param
        - x: codice unico per ogni cittadino da inviare al Governo in caso di positività
        - tempo: numero di secondi necessari per il calcolo del tampone, di default pari a 10
                simula l'intervallo di tempo in cui un cittadino attende l'esito nella realtà
    '''

    sleep(tempo)

    bit = randint(0, 1)   # al 50% esce 0 ed al 50% esce 1
    if bit == 0:
        print("ESITO NEGATIVO, contattare il paziente " + str(tabella[x]))

        tabella[x] = "0000000000000000"     # si azzera il conenuto informativo della tabella
        del tabella[x]      # si cancella il cittadino dalla tabella
    else:
        print("ESITO POSITIVO, contattare il paziente "+str(tabella[x])+" , comunicazione al server inviata")

        # indirizzo IP del server del Governo, sezione dedicata alla comunicazione col laboratorio
        gov = "https://127.0.0.1:443/lab/"


        # il metodo 'requests.get' permette di effettuare una richiesta https, in cui si verifica il certificato
        # attraverso il certificato indicato nel parametro 'verify'
        # Viene inoltre concatenato all'indirizzo IP, il messaggio da inviare, ovvero il parametro di
        # input presente nella funzione 'lab' nel file server.py
        r = requests.get(gov + x, verify="../CA/cacert.pem")

        tabella[x] = "0000000000000000"     # si azzera il conenuto informativo della tabella
        del tabella[x]      # si cancella il cittadino dalla tabella


# Creazione dell'applicazione server del Laboratorio
app = Flask(__name__)

# Tabella che associa ad ogni x il codice fiscale del cittadino che la aveva inviata
# In questo modo si tiene traccia dei cittadini in attesa dell'esito del tampone
tabella={}


@app.route('/cittadino/<x>')
def cittadino(x):
    '''
    Questa funzione viene invocata nel momento in cui il cittadino si connette al laboratorio.


    @:param:
        - x: codice che il cittadino invia al laboratorio
    @:return
        - messaggio di errore se ci sono stati problemi
        - sigma: firma digitale del laboratorio come illustrato nella documentazione
    '''

    # Per prima cosa si effettua il parsing dell'input, esso deve essere una stringa in esadecimale.
    # Nel caso in cui questa condizione non viene rispettata, si invia un messaggio di errore al cittadino.
    sanifica = re.findall("[a-f0-9]+", x)
    if len(sanifica) == 1 and len(sanifica[0]) == len(x):
        print("\nRicevuta X da un cittadino, siamo in attesa del responso del tampone...")

        tabella[x]="codicefiscale"  # stringa rappresentante il codice fiscale del cittadino

        # inizia il processo di calcolo del risultato del tampone, ovvero si invoca la funzione 'risultato_tampone'
        threading.Thread(target=risultato_tampone, kwargs={'x': x, 'tempo': 10}).start()

        # Firma del codice x attraverso la chiave privata del laboratorio, schema RSA con chiave a 4096 bits
        signature = private_key.sign(bytes.fromhex(x), padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                          salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        print("Invio di sigma completato")
        return str(signature.hex())

    else:
        return "Errore"


# Avvio del server del laboratorio in localhost sulla porta 444
app.run(port=444,ssl_context=('../certLab.pem', 'keyLab.pem'))

