
import requests
from flask import Flask

# Creazione dell'applicazione server del Proxy
app = Flask(__name__)

@app.route('/cittadino/<stringa>')
def cittadino(stringa):
    '''
    Questa funzione viene invocata nel momento in cui un'applicazione,
    ovvero il cittadino nel nostro sistema, si connette al Proxy.
    Inoltra il messaggio in arrivo dal cittadino al server del Governo.

    @:param:
        - stringa: messaggio che il cittadino invia tramite https al proxy
    @:return
        - risposta dal governo all'invio del messaggio del cittadino
    '''

    # indirizzo IP del server del governo, sezione dedicata alla comunicazione col cittadino
    gov = "https://127.0.0.1:443/cittadino/"


    # il metodo 'requests.get' permette di effettuare una richiesta https, in cui si verifica il certificato
    # attraverso il certificato indicato nel parametro 'verify'
    r = requests.get(gov + stringa,  verify="../CA/cacert.pem")     # messaggio di risposta dal server del governo


    if r.status_code == 200:    #il collegamento https non ha riscontrato problemi
        print("inoltro del messaggio al server eseguito correttamente")

    return r.text


# Avvio del server Proxy in localhost sulla porta classica di una connessione a internet, infatti
# il client, ovvero il cittadino, è supposto collegarsi dalla stessa macchina in questa simulazione.
app.run(port=8080,ssl_context=('../certProxy.pem', 'keyProxy.pem'))