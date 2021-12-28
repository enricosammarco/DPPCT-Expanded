Per la corretta esecuzione del sistema vanno installate le seguenti librerie python di cui si è fatto uso (alcune probabilmente già installate di default):

- flask
- cryptography
- re
- requests
- threading
- random
- time
- os

Si noti inoltre la presenza di un warning nel momento in cui si effettuano richieste https, ciò è dovuto al fatto che sono stati utilizzati solo i common name nella creazione dei certificati, mentre la libreria python utilizzata ha come default la ricerca nel SubjectAltName prima del Common name.
