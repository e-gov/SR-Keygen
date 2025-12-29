# SR-Keygen

Käesolev repositoorium sisaldab **operatiivset juhendmaterjali ja tehnilisi skripte**, mille eesmärk on võimaldada **Riigi Infosüsteemi Ametil (RIA)** luua usaldusnimekirja e-allkirjastamiseks vajalikud krüptovõtmed ja sertifikaadid **turvalises, kontrollitud ja võrguühenduseta keskkonnas**.

Projekt keskendub kordusvõimelisele, auditeeritavale ja standarditele vastavale protseduurile.

## Projekti eesmärk

- kirjeldada selge ja korratav protseduur krüptovõtmete loomiseks;
- tagada võtmete genereerimine **offline-keskkonnas**;
- kasutada riistvaralist võtmekaitset (PIV + YubiKey);
- võimaldada kaheosalise PIN-koodi protseduuri;
- pakkuda skriptitud ja testitud töövoogu;
- toetada auditit ja hilisemat kontrollitavust.

## Repositooriumi sisu

- **Operatiivjuhend** – samm-sammuline kirjeldus kogu protsessist alates ettevalmistusest kuni lõpetamiseni;
- **Installatsiooniskriptid** – offline-keskkonna ettevalmistamiseks vajalik tarkvara;
- **Võtmete ja sertifikaatide loomise skriptid** – krüptovõtmete genereerimine ja sertifikaatide väljastamine;
- **Testskriptid** – allkirjastamise ja sertifikaadi korrektse toimimise kontroll;
- **SHA256 sõrmejälgede manifest** – failide tervikluse kontrollimiseks.

## Olulised põhimõtted

- privaatvõtmed **ei lahku kunagi** riistvaralisest võtmekandjast;
- kogu kriitiline tegevus toimub võrguühenduseta;
- kõik sammud on dokumenteeritavad ja logitavad;
- protseduur ei eelda väliseid teenuseid ega pilvekomponente.