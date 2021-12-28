
import requests
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from utilities import sha256,simm_enc


# inizializzazione
sk0 = os.urandom(256)   # Calcolo dell'sk0, codice privato del cittadino
skt = sha256(sk0)       # Nella simulazione skt è sempre pari ad sk1 per semplicità
skt_hex = skt.hex()     # rappresentazione di skt in esadecimale


# contatto con il lab di analisi - cittadino fa il tampone
salt = os.urandom(256)  # calcolo della stringa casuale
salt_hex = salt.hex()

sha = sha256(salt+skt)  # calcolo della funzione di hash come illustrato nella documentazione
x = sha.hex()

# indirizzo IP del server del laboratorio, sezione dedicata alla comunicazione col cittadino
lab = "https://127.0.0.1:444/cittadino/"

# il metodo 'requests.get' permette di effettuare una richiesta https, in cui si verifica il certificato
# attraverso il certificato indicato nel parametro 'verify'
# Viene inoltre concatenato all'indirizzo IP, il messaggio da inviare, ovvero il parametro di
# input presente nella funzione 'cittadino' nel file lab.py
r = requests.get(lab+x,  verify="CA/cacert.pem")    # messaggio di risposta dal server del laboratorio

if r.status_code == 200:    #il collegamento https non ha riscontrato problemi
    print("Invio di x avvenuto correttamente")

# Contenuto della risposta del laboratorio
sigma = r.text
if sigma is not None:
    print("\nRicezione di sigma avvenuta correttamente")


print("\nAttesa dell'esito del tampone...")
conf = 0

# Ciclo di attesa input del cittadino
while not conf:
    print("\nDigita NO se hai ricevuto esito negativo al tampone, oppure se non vuoi comunicarlo.")
    answer = input("Digita SI se hai ricevuto la conferma di infezione dal laboratorio di analisi "
                    "e vuoi aiutare a contenere l'infezione condividendo questa informazione: ")


    if answer == "si" or answer =="SI" or answer == "Si":
        '''
        Il cittadino è risultato positivo e vuole comunicare le informazioni al server
        '''

        # Caricamento chiave pubblica del server del Governo
        # a partire dal suo certificato
        gov_public_key_file = open("certGov.pem", "rb")  # Apertura del file contenente il certificato
        gov_cert = x509.load_pem_x509_certificate(gov_public_key_file.read(),default_backend())  # Caricamento del certificato dal file
        gov_public_key = gov_cert.public_key()  # estrapolazione public key dal certificato

        # Calcolo dei dummy data illustrati nella relazione, in particolare in questa implementazione
        # questi dati altro non sono che una ripetizione della skt del cittadino
        dummy = str(skt_hex)

        # Composizione del messaggio da inviare al Governo tramite il Proxy
        stringa = dummy+","+sigma+","+str(skt_hex)+","+str(salt_hex)+","+str(14)
        m = bytes(stringa, 'utf-8')

        # Invocazione della funzione definita nel file 'utilities.py'
        simm_key, c = simm_enc(m)

        # Cifratura a chiave pubblica RSA
        # la chiave utilizzata è quella del Governo a 4096 bit
        # il plaintext da cifrare consiste nella chiave simmetrica utilizzata precedentemente
        simm_key_enc = gov_public_key.encrypt(simm_key,padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256())
                                                                 ,algorithm = hashes.SHA256(),label = None ))

        # Il messaggio che verrà inviato con https al Proxy sarà quindi formato dalla chiave
        # simmetrica cifrata e dal cyphertext 'c' del messaggio contenente le info del cittadino
        mex = str(simm_key_enc.hex())+"-"+str(c.hex())

        # indirizzo IP del server Proxy, sezione dedicata alla comunicazione col cittadino
        proxy = "https://127.0.0.1:8080/cittadino/"

        # Viene concatenato all'infdirizzo IP il messaggio da inviare, ovvero l'input 'stringa' presente
        # nella funzione 'cittadino' nel file 'proxy.py'
        r = requests.get(proxy+mex , verify="CA/cacert.pem")    # messaggio di risposta dal Proxy


        if r.text == "ok":
            conf = 1
            print("\nComunicazione verificata dal server, grazie")
        else:
            print("\nCodice non riconosciuto, riprovare...")

    if answer == "no" or answer == "NO" or answer == "No":
        '''
        Il cittadino è risultato negativo al tampone oppure ha preferito non condividere le sue informazioni
        '''
        print("OK, operazione terminata")
        break