use anyhow::{Context, Result, bail};
use pcsc::{Context as PcscContext, Scope};

use crate::{
    KeyKind, authenticate, connect, decode_ndef_text, get_uid, parse_key, read_block, write_block,
};

slint::include_modules!();

pub(crate) fn run() -> Result<()> {
    let ui = MainWindow::new().context("Création de la fenêtre Slint échouée")?;
    populate_readers(&ui);

    {
        let ui_weak = ui.as_weak();
        ui.on_refresh_readers(move || {
            if let Some(ui) = ui_weak.upgrade() {
                populate_readers(&ui);
            }
        });
    }

    {
        let ui_weak = ui.as_weak();
        ui.on_read_uid(move || {
            if let Some(ui) = ui_weak.upgrade() {
                run_op(&ui, "UID", |idx, _key, _kind| {
                    let ctx = PcscContext::establish(Scope::User)?;
                    let card = connect(&ctx, idx)?;
                    let uid = get_uid(&card)?;
                    Ok(format!("UID: {}", hex::encode_upper(&uid)))
                });
            }
        });
    }

    {
        let ui_weak = ui.as_weak();
        ui.on_read_block_action(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let block_str = ui.get_block_str().to_string();
                run_op(&ui, "Read", move |idx, key, kind| {
                    let block: u8 = block_str
                        .trim()
                        .parse()
                        .context("Numéro de bloc invalide")?;
                    let ctx = PcscContext::establish(Scope::User)?;
                    let card = connect(&ctx, idx)?;
                    authenticate(&card, block, &key, &kind)?;
                    let data = read_block(&card, block)?;
                    Ok(format!("Bloc {block:02}: {}", hex::encode_upper(&data)))
                });
            }
        });
    }

    {
        let ui_weak = ui.as_weak();
        ui.on_write_block_action(move || {
            if let Some(ui) = ui_weak.upgrade() {
                let block_str = ui.get_block_str().to_string();
                let data_hex = ui.get_write_data().to_string();
                run_op(&ui, "Write", move |idx, key, kind| {
                    let block: u8 = block_str
                        .trim()
                        .parse()
                        .context("Numéro de bloc invalide")?;
                    let data = hex::decode(data_hex.trim()).context("data_hex invalide")?;
                    if data.len() != 16 {
                        bail!("Les données doivent faire exactement 16 octets (32 hex)");
                    }
                    let ctx = PcscContext::establish(Scope::User)?;
                    let card = connect(&ctx, idx)?;
                    authenticate(&card, block, &key, &kind)?;
                    write_block(&card, block, &data)?;
                    Ok(format!("Bloc {block:02} écrit ({} octets)", data.len()))
                });
            }
        });
    }

    {
        let ui_weak = ui.as_weak();
        ui.on_dump_action(move || {
            if let Some(ui) = ui_weak.upgrade() {
                run_op(&ui, "Dump", |idx, key, kind| {
                    let ctx = PcscContext::establish(Scope::User)?;
                    let card = connect(&ctx, idx)?;
                    let mut out = String::new();
                    for block in 0u8..64 {
                        match authenticate(&card, block, &key, &kind)
                            .and_then(|_| read_block(&card, block))
                        {
                            Ok(data) => out.push_str(&format!(
                                "{block:02}: {}\n",
                                hex::encode_upper(&data)
                            )),
                            Err(e) => out.push_str(&format!("{block:02}: ERREUR ({e})\n")),
                        }
                    }
                    Ok(out.trim_end().to_string())
                });
            }
        });
    }

    {
        let ui_weak = ui.as_weak();
        ui.on_ndef_text_action(move || {
            if let Some(ui) = ui_weak.upgrade() {
                run_op(&ui, "NDEF", |idx, key, kind| {
                    let ctx = PcscContext::establish(Scope::User)?;
                    let card = connect(&ctx, idx)?;
                    let mut buf = Vec::new();
                    for block in 4u8..64 {
                        if block % 4 == 3 {
                            continue;
                        }
                        authenticate(&card, block, &key, &kind)?;
                        let data = read_block(&card, block)?;
                        buf.extend_from_slice(&data);
                        if buf.contains(&0xFE) {
                            break;
                        }
                    }
                    let (lang, text) = decode_ndef_text(&buf)?;
                    Ok(format!("[{lang}] {text}"))
                });
            }
        });
    }

    {
        let ui_weak = ui.as_weak();
        ui.on_clear_output(move || {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_output("".into());
                ui.set_status("Sortie effacée.".into());
            }
        });
    }

    ui.run().context("Boucle d'événements Slint échouée")?;
    Ok(())
}

fn populate_readers(ui: &MainWindow) {
    match read_reader_names() {
        Ok(names) => {
            let count = names.len();
            let model = slint::VecModel::from(
                names
                    .into_iter()
                    .map(slint::SharedString::from)
                    .collect::<Vec<_>>(),
            );
            ui.set_readers(slint::ModelRc::new(model));
            if count == 0 {
                ui.set_status("Aucun lecteur détecté.".into());
            } else {
                ui.set_status(format!("{count} lecteur(s) détecté(s).").into());
            }
        }
        Err(e) => {
            ui.set_status(format!("Erreur lecteurs: {e}").into());
        }
    }
}

fn read_reader_names() -> Result<Vec<String>> {
    let ctx = PcscContext::establish(Scope::User)?;
    let mut buf = [0u8; 2048];
    Ok(ctx
        .list_readers(&mut buf)?
        .map(|r| r.to_string_lossy().into_owned())
        .collect())
}

fn run_op<F>(ui: &MainWindow, label: &str, f: F)
where
    F: FnOnce(usize, [u8; 6], KeyKind) -> Result<String>,
{
    let idx = ui.get_reader_index() as usize;
    let key_hex = ui.get_key_hex().to_string();
    let key_type_str = ui.get_key_type().to_string();

    let result = (|| -> Result<String> {
        let key = parse_key(&key_hex)?;
        let kind = match key_type_str.as_str() {
            "A" | "a" => KeyKind::A,
            "B" | "b" => KeyKind::B,
            other => bail!("Type de clé invalide: {other}"),
        };
        f(idx, key, kind)
    })();

    match result {
        Ok(msg) => {
            append_output(ui, &format!("[{label}] {msg}"));
            ui.set_status(format!("{label}: OK").into());
        }
        Err(e) => {
            append_output(ui, &format!("[{label}] ERREUR: {e}"));
            ui.set_status(format!("{label}: erreur").into());
        }
    }
}

fn append_output(ui: &MainWindow, line: &str) {
    let mut out = ui.get_output().to_string();
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(line);
    ui.set_output(out.into());
}
