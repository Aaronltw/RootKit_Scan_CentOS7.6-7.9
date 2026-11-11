#[path = "../crypto.rs"]
#[allow(dead_code)]
mod crypto;

use std::process::ExitCode;

const USAGE: &str = "\
rootkit-scan 報告解密工具
用法：
  rootkit-scan-decrypt --genkey [--out 私鑰檔]
      在你自己的電腦上產一對金鑰。公鑰印在螢幕上（交給打包掃描器的人），
      私鑰寫到檔案（預設 rootkit-scan-private.key）。私鑰請收好，只有它能解密，
      絕不要放到被掃描的主機。
  rootkit-scan-decrypt --decrypt 報告.enc --key 私鑰檔 [--out 報告.txt]
      用你的私鑰把加密報告還原。不指定 --out 就印在螢幕上。
";

struct Args {
    genkey: bool,
    decrypt: Option<String>,
    key: Option<String>,
    out: Option<String>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        genkey: false,
        decrypt: None,
        key: None,
        out: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{} 後面要接值", name));
        match arg.as_str() {
            "--genkey" => a.genkey = true,
            "--decrypt" => a.decrypt = Some(value("--decrypt")?),
            "--key" => a.key = Some(value("--key")?),
            "--out" => a.out = Some(value("--out")?),
            "--help" | "-h" => {
                println!("{}", USAGE);
                std::process::exit(0);
            }
            other => return Err(format!("不認得的選項 {}\n{}", other, USAGE)),
        }
    }
    if a.genkey && a.decrypt.is_some() {
        return Err("--genkey 與 --decrypt 不能一起用".into());
    }
    if !a.genkey && a.decrypt.is_none() {
        return Err(format!("要用 --genkey 或 --decrypt\n{}", USAGE));
    }
    Ok(a)
}

fn create_new(path: &str) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

fn do_genkey(out: Option<&str>) -> Result<(), String> {
    use std::io::Write;
    let (pubk, seck) = crypto::generate();
    let path = out.unwrap_or("rootkit-scan-private.key");
    let mut f = create_new(path).map_err(|e| {
        format!(
            "寫不出私鑰檔 {}：{}（若已存在，請改用 --out 指定別的路徑）",
            path, e
        )
    })?;
    writeln!(
        f,
        "# rootkit-scan 私鑰，請收好；只有它能解密報告，絕不要放到被掃描的主機。"
    )
    .and_then(|_| writeln!(f, "{}", seck))
    .map_err(|e| format!("寫不出私鑰檔 {}：{}", path, e))?;
    println!("公鑰（打包掃描器時帶入環境變數 ROOTKIT_SCAN_PUBKEY，可公開）：");
    println!("{}", pubk);
    println!();
    println!(
        "私鑰已寫到：{}（請收好、備份，遺失就再也解不開舊報告）",
        path
    );
    Ok(())
}

fn do_decrypt(enc_path: &str, key: Option<&str>, out: Option<&str>) -> Result<(), String> {
    let key_path = key.ok_or("解密要用 --key 指定你的私鑰檔")?;
    let sec = std::fs::read_to_string(key_path)
        .map_err(|e| format!("讀不到私鑰檔 {}：{}", key_path, e))?;
    let data = std::fs::read(enc_path).map_err(|e| format!("讀不到 {}：{}", enc_path, e))?;
    let plain = crypto::unseal(&sec, &data)?;
    match out {
        Some(path) => {
            std::fs::write(path, &plain).map_err(|e| format!("寫不出 {}：{}", path, e))?;
            eprintln!("已解密寫到 {}", path);
        }
        None => {
            use std::io::Write;
            std::io::stdout()
                .write_all(&plain)
                .map_err(|e| format!("印不出來：{}", e))?;
        }
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let a = parse()?;
    if a.genkey {
        return do_genkey(a.out.as_deref());
    }
    if let Some(enc) = &a.decrypt {
        return do_decrypt(enc, a.key.as_deref(), a.out.as_deref());
    }
    Ok(())
}

fn main() -> ExitCode {
    if let Err(e) = run() {
        eprintln!("rootkit-scan-decrypt：{}", e);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
