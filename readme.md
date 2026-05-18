# Description

`facts` est un utilitaire en ligne de commande écrit en Rust pour lire et
écrire des cartes RFID/NFC via un lecteur **ACR122U** (PC/SC), avec un
support de premier ordre pour les cartes **MIFARE Classic 1K**.

L'outil parle directement à la carte en APDU (pas d'abstraction `libnfc`)
et reste suffisamment minimaliste pour servir aussi bien d'outil pratique
que de référence sur le protocole.

## Les objectifs

- **Lire** rapidement l'UID, un bloc précis ou un dump complet d'une carte
  MIFARE Classic 1K.
- **Écrire** dans n'importe quel bloc de données (16 octets) avec
  authentification clé A/B.
- **Documenter** les APDU PC/SC du couple ACR122U + MIFARE Classic dans un
  code source lisible (≈170 lignes de Rust).
- **Permettre** la manipulation manuelle de messages NDEF (Text, URI…) en
  composant le TLV à la main, sans dépendre d'une bibliothèque NDEF.
- **Servir de base** pour ajouter d'autres familles de cartes (Ultralight,
  NTAG, DESFire) ou d'autres lecteurs PC/SC.

## Prérequis

- Rust (edition 2024)
- `pcsc-lite` et son service `pcscd`
- Lecteur ACR122U branché en USB

Sur Fedora :

```bash
sudo dnf install -y pkgconf pcsc-lite-devel pcsc-lite
sudo systemctl enable --now pcscd
```

## Build

```bash
cargo build --release
```

Binaire : `./target/release/facts`

## Options globales

| Option         | Défaut         | Description                              |
|----------------|----------------|------------------------------------------|
| `--reader N`   | `0`            | Index du lecteur si plusieurs branchés   |
| `--key HEX`    | `FFFFFFFFFFFF` | Clé MIFARE 6 octets (12 hex)             |
| `--key-type`   | `a`            | `a` ou `b`                               |

> **Cartes NFC formatées (NDEF)** : les secteurs de données utilisent souvent la
> clé B `FFFFFFFFFFFF` (clé A non standard). Si l'authentification échoue avec
> les valeurs par défaut, retentez avec `--key-type b`.

## Commandes

### `list` — lister les lecteurs PC/SC

```bash
$ facts list
[0] ACS ACR122U PICC Interface 00 00
[1] Alcor Link AK9563 01 00
```

L'index entre crochets sert pour `--reader N` (par défaut `0`).

### `uid` — lire l'UID de la carte

```bash
$ facts --reader 0 uid
UID: 835A8F60
```

UID de 4 octets (MIFARE Classic 1K) ou 7 octets (Ultralight/NTAG).

### `read <block>` — lire un bloc (16 octets)

```bash
$ facts --reader 0 --key-type b read 4
Bloc 04: 0317D1011354026672626F6E6A6F7572
```

Numéro de bloc : 0–63 pour une MIFARE Classic 1K. L'authentification se fait
automatiquement avec `--key` / `--key-type`.

### `write <block> <hex>` — écrire 16 octets dans un bloc

Le hex doit faire exactement 32 caractères (16 octets), **sans espaces** :

```bash
$ facts --reader 0 --key-type b write 4 0317D1011354026672626F6E6A6F7572
Bloc 04 écrit.
```

> ⚠ N'écrivez **jamais** dans un bloc *trailer* (3, 7, 11, … 63) sans connaître
> précisément les access bits et clés à inscrire — vous pouvez verrouiller
> définitivement le secteur.

### `dump` — dump complet d'une MIFARE Classic 1K

```bash
$ facts --reader 0 --key-type b dump
00: 835A8F6036880400C844002000000015
01: 140103E103E103E103E103E103E103E1
02: 03E103E103E103E103E103E103E103E1
03: 000000000000787788C1000000000000
04: 0317D1011354026672626F6E6A6F7572
05: 206C65206D6F6E6465FE000000000000
...
63: 0000000000007F078840000000000000
```

Les blocs dont l'authentification échoue sont marqués `ERREUR (...)` — utile
pour identifier un secteur dont la clé n'est pas la valeur fournie.

## Exemple : écrire un message NDEF Text

Une MIFARE Classic 1K formatée NFC stocke les données NDEF à partir du
**bloc 4** (secteur 1, après le MAD). Le format d'un record Text est :

```
03 LL                           ← NDEF Message TLV (LL = longueur record)
D1 01 PL 54                     ← record SR, type "T", payload PL octets
02 <lang1> <lang2>              ← status (UTF-8 + lang 2 chars) + code langue
<texte UTF-8...>                ← payload texte
FE                              ← terminator TLV
```

Pour écrire **« bonjour le monde »** (16 octets de texte, langue `fr`) :

```bash
# Bloc 4 : 03 17 D1 01 13 54 02 66 72  b  o  n  j  o  u  r
facts --reader 0 --key-type b write 4 0317D1011354026672626F6E6A6F7572

# Bloc 5 : ' ' l  e  ' ' m  o  n  d  e  FE 00 00 00 00 00 00
facts --reader 0 --key-type b write 5 206C65206D6F6E6465FE000000000000

# Bloc 6 : effacer tout résidu après le terminator FE
facts --reader 0 --key-type b write 6 00000000000000000000000000000000
```

Vérification :

```bash
$ facts --reader 0 --key-type b read 4
Bloc 04: 0317D1011354026672626F6E6A6F7572
$ facts --reader 0 --key-type b read 5
Bloc 05: 206C65206D6F6E6465FE000000000000
```

La carte est ensuite lisible par n'importe quelle app NFC standard (Android,
NFC Tools, etc.).

## Exemple : lire le texte d'un tag NDEF

Pour récupérer le texte stocké, on lit les blocs à partir du bloc 4 et on
décode le TLV à la main. L'en-tête d'un record Text avec code langue 2 lettres
fait **9 octets** (`03 LL D1 01 PL 54 02 L1 L2`) ; le texte commence juste
après et s'arrête au terminator `FE`.

Décodage à la main, à partir des blocs lus précédemment :

```
0317D101135402 6672  <- en-tête TLV+record (7 octets) + langue "fr" (2 octets)
              ^^^^
              langue
                    626F6E6A6F7572206C65206D6F6E6465 FE  <- payload + terminator
                    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                    "bonjour le monde" (UTF-8)
```

One-liner shell qui lit les deux blocs, retire l'en-tête (18 caractères hex
= 9 octets pour une langue 2-lettres) et stoppe à `FE` :

```bash
$ { facts --reader 0 --key-type b read 4 | awk '{print $NF}'; \
    facts --reader 0 --key-type b read 5 | awk '{print $NF}'; } \
  | tr -d '\n' | cut -c19- | sed 's/FE.*$//' \
  | perl -ne 'chomp; print pack("H*", $_)'; echo
bonjour le monde
```

> Si le code langue fait 3 lettres (`02 65 6E 67` pour "eng"), l'en-tête fait
> 10 octets → remplacer `cut -c19-` par `cut -c21-`. Le second octet du record
> (`PL`) donne la longueur exacte du payload, status byte inclus.

## APDU utilisés (ACR122U / PC/SC)

| Opération            | APDU                                  |
|----------------------|---------------------------------------|
| Get UID              | `FF CA 00 00 00`                      |
| Load Auth Key        | `FF 82 00 00 06 <K1..K6>`             |
| Authenticate Block   | `FF 86 00 00 05 01 00 <BLK> <KT> 00`  |
| Read Binary          | `FF B0 00 <BLK> 10`                   |
| Update Binary        | `FF D6 00 <BLK> 10 <D1..D16>`         |

`KT` = `0x60` pour clé A, `0x61` pour clé B.

## Limites

- Pas de gestion MIFARE Ultralight, NTAG ou DESFire pour l'instant.
- Pas de découverte automatique des clés (mfoc/mfcuk).
- Les blocs *trailer* (3, 7, 11, …) contiennent les clés A/B et bits d'accès :
  attention à ne pas y écrire n'importe quoi.

## Licence

MIT
