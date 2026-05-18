use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use pcsc::{Card, Context as PcscContext, Protocols, Scope, ShareMode};

#[derive(Parser)]
#[command(name = "facts", about = "Lecture/écriture RFID via ACR122U (MIFARE Classic)")]
struct Cli {
    /// Index du lecteur si plusieurs sont branchés
    #[arg(long, default_value_t = 0)]
    reader: usize,

    /// Clé MIFARE en hex (12 caractères = 6 octets). Défaut : FFFFFFFFFFFF
    #[arg(long, default_value = "FFFFFFFFFFFF")]
    key: String,

    /// Type de clé : a ou b
    #[arg(long, value_enum, default_value_t = KeyKind::A)]
    key_type: KeyKind,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Default, clap::ValueEnum)]
enum KeyKind {
    #[default]
    A,
    B,
}

#[derive(Subcommand)]
enum Cmd {
    /// Liste les lecteurs PC/SC disponibles
    List,
    /// Lit l'UID de la carte présente
    Uid,
    /// Lit un bloc (0..63 pour MIFARE Classic 1K)
    Read { block: u8 },
    /// Écrit 16 octets (hex, 32 caractères) dans un bloc
    Write { block: u8, data_hex: String },
    /// Dump complet d'une MIFARE Classic 1K (64 blocs)
    Dump,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let ctx = PcscContext::establish(Scope::User).context("Impossible d'initialiser PC/SC")?;

    match cli.cmd {
        Cmd::List => list_readers(&ctx),
        Cmd::Uid => {
            let card = connect(&ctx, cli.reader)?;
            let uid = get_uid(&card)?;
            println!("UID: {}", hex::encode_upper(&uid));
            Ok(())
        }
        Cmd::Read { block } => {
            let card = connect(&ctx, cli.reader)?;
            let key = parse_key(&cli.key)?;
            authenticate(&card, block, &key, &cli.key_type)?;
            let data = read_block(&card, block)?;
            println!("Bloc {block:02}: {}", hex::encode_upper(&data));
            Ok(())
        }
        Cmd::Write { block, data_hex } => {
            let data = hex::decode(data_hex.trim()).context("data_hex invalide")?;
            if data.len() != 16 {
                bail!("Les données doivent faire exactement 16 octets (32 hex)");
            }
            let card = connect(&ctx, cli.reader)?;
            let key = parse_key(&cli.key)?;
            authenticate(&card, block, &key, &cli.key_type)?;
            write_block(&card, block, &data)?;
            println!("Bloc {block:02} écrit.");
            Ok(())
        }
        Cmd::Dump => {
            let card = connect(&ctx, cli.reader)?;
            let key = parse_key(&cli.key)?;
            for block in 0u8..64 {
                match authenticate(&card, block, &key, &cli.key_type)
                    .and_then(|_| read_block(&card, block))
                {
                    Ok(data) => println!("{block:02}: {}", hex::encode_upper(&data)),
                    Err(e) => println!("{block:02}: ERREUR ({e})"),
                }
            }
            Ok(())
        }
    }
}

fn list_readers(ctx: &PcscContext) -> Result<()> {
    let mut buf = [0u8; 2048];
    let readers = ctx.list_readers(&mut buf)?;
    let mut found = false;
    for (i, r) in readers.enumerate() {
        println!("[{i}] {}", r.to_string_lossy());
        found = true;
    }
    if !found {
        println!("Aucun lecteur détecté.");
    }
    Ok(())
}

fn connect(ctx: &PcscContext, index: usize) -> Result<Card> {
    let mut buf = [0u8; 2048];
    let reader = ctx
        .list_readers(&mut buf)?
        .nth(index)
        .ok_or_else(|| anyhow!("Lecteur n°{index} introuvable"))?;
    let card = ctx
        .connect(reader, ShareMode::Shared, Protocols::ANY)
        .context("Connexion à la carte échouée (carte absente ?)")?;
    Ok(card)
}

fn transmit(card: &Card, apdu: &[u8]) -> Result<Vec<u8>> {
    let mut resp = [0u8; 258];
    let r = card.transmit(apdu, &mut resp).context("APDU échoué")?;
    if r.len() < 2 {
        bail!("Réponse APDU trop courte");
    }
    let sw1 = r[r.len() - 2];
    let sw2 = r[r.len() - 1];
    if sw1 != 0x90 || sw2 != 0x00 {
        bail!("APDU refusé : SW={sw1:02X}{sw2:02X}");
    }
    Ok(r[..r.len() - 2].to_vec())
}

fn get_uid(card: &Card) -> Result<Vec<u8>> {
    // FF CA 00 00 00 — Get Data (UID)
    transmit(card, &[0xFF, 0xCA, 0x00, 0x00, 0x00])
}

fn parse_key(s: &str) -> Result<[u8; 6]> {
    let v = hex::decode(s).context("Clé hex invalide")?;
    if v.len() != 6 {
        bail!("La clé doit faire 6 octets (12 hex)");
    }
    let mut k = [0u8; 6];
    k.copy_from_slice(&v);
    Ok(k)
}

fn authenticate(card: &Card, block: u8, key: &[u8; 6], kind: &KeyKind) -> Result<()> {
    // 1. Charger la clé dans le slot 0 : FF 82 00 00 06 K1..K6
    let mut load = vec![0xFF, 0x82, 0x00, 0x00, 0x06];
    load.extend_from_slice(key);
    transmit(card, &load).context("Chargement de la clé échoué")?;

    // 2. Authentifier le bloc : FF 86 00 00 05 01 00 BLK KT 00
    let key_type_byte = match kind {
        KeyKind::A => 0x60,
        KeyKind::B => 0x61,
    };
    let auth = [
        0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block, key_type_byte, 0x00,
    ];
    transmit(card, &auth).context("Authentification échouée")?;
    Ok(())
}

fn read_block(card: &Card, block: u8) -> Result<Vec<u8>> {
    // FF B0 00 BLK 10 — Read Binary (16 octets)
    transmit(card, &[0xFF, 0xB0, 0x00, block, 0x10])
}

fn write_block(card: &Card, block: u8, data: &[u8]) -> Result<()> {
    // FF D6 00 BLK 10 D1..D16 — Update Binary
    let mut apdu = vec![0xFF, 0xD6, 0x00, block, 0x10];
    apdu.extend_from_slice(data);
    transmit(card, &apdu).map(|_| ())
}
