# DPPCT-Expanded
Progetto sviluppato durante il corso di Cybersecurity (UniSa - DIEM - Anno accademico 2019/2020)

Tema del progetto: realizzare un sistema di tracciamento dei contatti tra le persone mediante pseudonimi su smartphone con tecnologia bluetooth low energy, con decentralizzazione dei dati resi disponibili per studi epidemiologici.

### Contenuto della relazione:
1) Proposta di progetto.
2) Discussione sulle proprietà di confidenzialità ed integrità che si intendono gestire e descrizione degli avversari.
3) Progettazione del sistema.
4) Analisi della confidenzialità e della integrità del sistema proposto.
5) Implementazione e guida all'uso

### Implementazione:
L’implementazione consiste nella simulazione del protocollo che regola la comunicazione tra il cittadino infetto, il laboratorio di analisi ed il Governo. 
Il linguaggio di programmazione utilizzato è Python, per le funzioni crittografiche è stata utilizzata la libreria cryptography, le entità coinvolte sono implementate come Flask server e comunicano tra loro attraverso richieste https verificando i certificati rilasciati dall'autorità centrale.
