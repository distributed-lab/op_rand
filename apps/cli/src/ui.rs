use console::{Emoji, style};

pub static CHECK: Emoji<'_, '_> = Emoji("✅ ", "");
pub static GEAR: Emoji<'_, '_> = Emoji("⚙️ ", "");
pub static SHIELD: Emoji<'_, '_> = Emoji("🛡️ ", "");
pub static KEY: Emoji<'_, '_> = Emoji("🔑 ", "");
pub static CHAIN: Emoji<'_, '_> = Emoji("⛓️ ", "");
pub static RADIO: Emoji<'_, '_> = Emoji("📡 ", "");
pub static SPARKLES: Emoji<'_, '_> = Emoji("✨ ", "");
pub static CLOCK: Emoji<'_, '_> = Emoji("⏰ ", "");
pub static TARGET: Emoji<'_, '_> = Emoji("🎯 ", "");
pub static ROCKET: Emoji<'_, '_> = Emoji("🚀 ", "");
pub static LOCK: Emoji<'_, '_> = Emoji("🔒 ", "");

pub fn header(text: &str) -> String {
    format!(
        "\n{}\n{}\n{}",
        "═".repeat(80),
        style(text).bold().cyan(),
        "═".repeat(80)
    )
}

pub fn section_header(text: &str) -> String {
    style(format!("┌─ {}", text)).bold().blue().to_string()
}

pub fn success_footer(text: &str) -> String {
    format!(
        "\n{}\n{}\n{}\n",
        "═".repeat(80),
        style(text).bold().green(),
        "═".repeat(80)
    )
}

pub fn format_bitcoin_amount(satoshis: u64) -> String {
    let btc_amount = satoshis as f64 / 100_000_000.0;
    format!(
        "{} satoshis ({} BTC)",
        style(satoshis.to_string()).bright().green().bold(),
        style(format!("{:.8}", btc_amount)).bright().green()
    )
}
