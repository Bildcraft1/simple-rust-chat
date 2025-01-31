# SRC (Simple Rust Chat)

Simple Rust Chat è una chat Client/Server che permette di fare le seguenti azioni:
- Chattare con altri utenti in canali per topic
- Chattare con una persona sola (DMs)
- Inviare i file tra utenti
- Possibilità di amministrare la chat con comandi di /kick o /ban

La chat è basata molto sull'idea di una chat IRC (inizialmente il progetto aveva come scopo la creazione di un server IRC da utilizzare con dei clienti IRC come Halloy o mIRC)

## Protocolli utilizzati

Il server utilizza TCP/IP come protocollo per la trasmissione dei dati in rete. I pacchetti sono composti da un pacchetto prestabilito

```
    /*
        Specifications of the packet
        32 bytes - Command name
        512 bytes - Command argument
        if command is empty then it is a message
    */
```

La chat è sicura usando x25519-dalek e AES-128 per criptare i messaggi e i dati dei file che vengono inviati. Lo scambio di chiavi viene effettuato con Diffie Hellman

