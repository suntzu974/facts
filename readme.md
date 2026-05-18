# facts

CLI Rust pour lire et écrire des cartes RFID/NFC via un lecteur **ACR122U** (PC/SC),
avec support des cartes **MIFARE Classic 1K**.

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

## Commandes

```bash
# Lister les lecteurs PC/SC détectés
facts list

# Lire l'UID de la carte présente
facts uid

# Lire le bloc 4 (clé par défaut FFFFFFFFFFFF, key A)
facts read 4

# Écrire 16 octets (32 caractères hex) dans le bloc 4
facts write 4 00112233445566778899AABBCCDDEEFF

# Dump complet d'une MIFARE Classic 1K (blocs 0 à 63)
facts dump
```

## Options globales

| Option         | Défaut         | Description                              |
|----------------|----------------|------------------------------------------|
| `--reader N`   | `0`            | Index du lecteur si plusieurs branchés   |
| `--key HEX`    | `FFFFFFFFFFFF` | Clé MIFARE 6 octets (12 hex)             |
| `--key-type`   | `a`            | `a` ou `b`                               |

Exemple avec clé custom :

```bash
facts --key A0A1A2A3A4A5 --key-type b read 7
```

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
