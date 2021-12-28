
from flask import Flask
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from utilities import sha256,simm_dec
import re

# Lista delle x che vengono inviate dal laboratorio di analisi, ovvero le x dei cittadini infetti
lista_x = []

# Caricamento in memoria della chiave privata del server Governo a partire dal file privato
with open("keyGov.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(),password = None,backend=default_backend())

# Caricamento chiave pubblica del laboratorio a partire dal suo certificato
lab_public_key_file = open("../certLab.pem", "rb")      # Apertura del file contenente il certificato
lab_cert = x509.load_pem_x509_certificate(lab_public_key_file.read(), default_backend())    # Caricamento del certificato dal file
lab_public_key = lab_cert.public_key()  # estrapolazione public key dal certificato

# Creazione dell'applicazione server
app = Flask(__name__)

@app.route('/lab/<x>')
def lab(x):
    '''
    Questa funzione viene invocata nel momento in cui il laboratorio
    si connette al server del Governo per inviargli la x di un cittadino infetto.
    Aggiunge la x del cittadino alla lista in memoria.

    @:param:
       - x: codice univoco di un cittadino
    @:return
       - messaggio di errore o di corretta esecuzione
    '''

    # Per prima cosa si effettua il parsing dell'input, esso deve essere una stringa in esadecimale.
    # Nel caso in cui questa condizione non viene rispettata, si invia un messaggio di errore al laboratorio.
    sanifica = re.findall("[a-f0-9]+",x)
    if len(sanifica) == 1 and len(sanifica[0]) == len(x):

        print("\nX ricevuto dal lab di analisi")
        lista_x.append(bytes.fromhex(x))    # Aggiunta della x alla lista
        return "saved"

    else:
        return "Errore"


@app.route('/cittadino/<ciphertext>')
def cittadino(ciphertext):
    '''
    Questa funzione viene invocata nel momento in cui il cittadino, attraverso il Proxy,
    si connette al server del Governo per inviargli le info riguardanti l'infezione.
    Aggiunge la x del cittadino alla lista in memoria.

    @:param:
       - ciphertext: informazioni riguardanti l'infezione cifrate come illustrato nella documentazione
    @:return
        - messaggio di errore dovuto a problemi di input, oppure ad un fallimento nella verifica della
            firma del laboratorio, oppure all'arrivo di una x non presente nella lista in memoria
        - oppure un messaggio di corretta ricezione delle informazioni
    '''

    # Per prima cosa si effettua il parsing dell'input, esso deve essere una stringa in esadecimale.
    # Nel caso in cui questa condizione non viene rispettata, si invia un messaggio di errore al laboratorio.
    sanifica = re.findall("[a-f0-9-]+", ciphertext)
    if len(sanifica) == 1 and len(sanifica[0]) == len(ciphertext):

        # Si estrapola dal messaggio in arrivo la chiave simmetrica di Fernet cifrata
        # e il cyphertext delle informazioni inviate dal cittadino
        simm_key_enc,c = ciphertext.split("-")

        # Si decifra la chiave simmetrica attraverso la chiave privata del Governo
        simm_key = private_key.decrypt(bytes.fromhex(simm_key_enc),padding.OAEP(
            mgf = padding.MGF1(algorithm=hashes.SHA256()), algorithm = hashes.SHA256(),label = None))

        # Invocazione della funzione definita nel file 'utilities.py'
        stringa = simm_dec(simm_key,bytes.fromhex(c))

        stringa = str(stringa)
        sk_old,sigma,skt,salt,t = stringa.split(",")    # dal messaggio decifrato si estrapolano le informazioni

        # Si calcola la x che ci si aspetta di trovare nella lista a partire dalle informazioni che
        # il cittadino ha inviato, in pratica ci si assicura che il cittadino ha utilizzato la stessa
        # skt nella comunicazione con il laboratorio e nella comunicazione con il Proxy
        skt_b = bytes.fromhex(skt)
        salt_b = bytes.fromhex(salt)
        message = sha256(salt_b+skt_b)

        sigma = bytes.fromhex(sigma)
        try:
            # Si verifica la firma del laboratorio di analisi, ovvero sigma, attraverso la public key dello stesso
            lab_public_key.verify(sigma, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                              salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        except Exception as e:
            #nel caso in cui la verify non andasse a buon fine viene lanciata un eccezione che dunque
            #viene catturata e si comunica al cittadino che la firma che ha inviato non è valida
            print(e)
            return "firma non valida"

        print("verifica della firma avvenuta con successo\n")

        trovato = 0
        for i in lista_x:  # Si scorre tutta la lista controllando ogni elemento
            if message == i:
                lista_x.remove(i)  # Se c'è una corrispondenza, si cancella l'elemento dalla lista
                trovato = 1
                print("X comunicato dal cittadino trovato nel database dei positivi comunicati dal lab di analisi")

        if trovato:
            return "ok"
        else:
            print("Identificativo effimero non trovato")
            return "non trovato"
    else:
        return "Errore"


# Avvio del server del laboratorio in localhost sulla porta 444
app.run(port=443,ssl_context=('../certGov.pem', 'keyGov.pem'))