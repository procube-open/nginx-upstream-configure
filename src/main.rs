use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use log::{error, warn, info};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::Deserialize;
use tokio::task::JoinHandle;
use tokio::signal::unix::{signal, SignalKind};
use tokio::process::{Child, Command};
use trust_dns_resolver::config::*;
use futures::future::try_join_all;
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct UpstreamConfig {
    name: String,
    fqdn: String,
    #[serde(default = "default_maxips")]
    maxips: usize,
    port: Option<u16>,
}

fn default_maxips() -> usize {
    1
}

#[derive(Debug, Clone)]
struct IpEntry {
    ip: IpAddr,
    registered_at: Instant,
}
#[tokio::main]
async fn main() -> Result<()> {
    // ロガーの初期化
    env_logger::init();

    // /etc/nginx/upstreams.d の下の設定ファイルを読み込む
    let upstreams_dir = Path::new("/etc/nginx/upstreams.d");
    let mut upstream_configs = HashMap::new();
    for entry in fs::read_dir(upstreams_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("yml") {
            let config_str = fs::read_to_string(&path)?;
            let config: UpstreamConfig = serde_yaml::from_str(&config_str)?;
            if upstream_configs.contains_key(&config.name) {
                return Err(anyhow!("upstream名 '{}' が重複しています", config.name));
            }
            upstream_configs.insert(config.name.clone(), config);
        }
    }

    // upstream ごとの IP アドレステーブルを初期化
    let ip_tables: Arc<Mutex<HashMap<String, Vec<IpEntry>>>> = Arc::new(Mutex::new(HashMap::new()));

    // 初期 upstream コンフィグファイルを生成
    for (upstream_name, _) in upstream_configs.clone() {
        create_upstream_config(&upstream_name, &[], None, 0, Path::new("/etc/nginx/conf.d"))?;
    }

    // nginx を起動
    let mut nginx_process = start_nginx()?;
    let nginx_pid = Pid::from_raw(nginx_process.id().unwrap() as i32);

    // シグナルハンドラーの設定
    let shutdown_signal = Arc::new(Mutex::new(false));
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigquit = signal(SignalKind::quit())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    // 設定ファイルごとに処理を並列に実行
    let handles: Arc<Mutex<Vec<JoinHandle<Result<()>>>>> = Arc::new(Mutex::new(Vec::new()));
    for (upstream_name, config) in upstream_configs.clone() {
        let shutdown_signal = shutdown_signal.clone();
        let ip_tables = ip_tables.clone();
        let handle: JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async move {
            // DNS Resolver の設定
            let resolver =
                TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
            loop {
                // DNS で FQDN を問い合わせ
                let mut ip_addresses = Vec::new();
                let mut min_ttl = 30;
                match resolver.lookup_ip(&config.fqdn).await {
                    Ok(response) => {
                        let now = Instant::now();
                        min_ttl = response.valid_until().duration_since(now).as_secs() as u32;
                        for record in response.iter() {
                            ip_addresses.push(record);
                        }
                        let mut my_ip_tables = ip_tables.lock().unwrap();
                        if let Some(ip_table) = my_ip_tables.get_mut(&upstream_name) {
                            if update_ip_table(&ip_addresses, ip_table) {
                                info!(
                                    "update upstream config: {}",
                                    ip_addresses
                                        .iter()
                                        .map(|ip| ip.to_string())
                                        .collect::<Vec<String>>()
                                        .join(", ")
                                );
                                // upstream コンフィグファイルを更新
                                create_upstream_config(
                                    &upstream_name,
                                    ip_table,
                                    config.port,
                                    config.maxips,
                                    Path::new("/etc/nginx/conf.d"),
                                )?;
                                // nginx をリロード
                                reload_nginx(nginx_pid)?;
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "fail to DNS Query fqdn={} for upstream {}: {}",
                            config.fqdn, upstream_name, e
                        );
                        // DNS 問い合わせに失敗した場合は IP アドレステーブルを空にする
                        let mut my_ip_tables = ip_tables.lock().unwrap();
                        let ip_table = my_ip_tables.get_mut(&upstream_name).unwrap();
                        ip_table.clear();
                        create_upstream_config(
                            &upstream_name,
                            &[],
                            None,
                            config.maxips,
                            Path::new("/etc/nginx/conf.d"),
                        )?;
                    }
                }

                // DNS の TTL が切れるかシャットダウンシグナルを受信するまで sleep
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(min_ttl as u64)) => {},
                    _ = async {
                        *shutdown_signal.lock().unwrap()
                    } => {
                        info!("Shutdown signal received. Terminate thread...");
                        return Ok(());
                    },
                }
            }
        });
        handles.lock().unwrap().push(handle);
    }

    // すべてのタスクを並行して実行し、どれかが終了したら shutdown_signal を true にする
    let mut exit_code = 0;
    tokio::select! {
        result = try_join_all(handles.lock().unwrap().drain(..)) => {
            if let Err(e) = result {
                error!("An error occurred in the upstream configuration thread: {}", e);
                exit_code = 1;
            }
            *shutdown_signal.lock().unwrap() = true;
        },
        result = nginx_process.wait() => {
            match result {
                Ok(status) => {
                    if status.success() {
                        info!("nginx process exited successfully");
                    } else {
                        error!("nginx process exited with error: {}", status);
                        exit_code = 1;
                    }
                },
                Err(e) => {
                    error!("An error occurred while waiting for nginx process: {}", e);
                    exit_code = 1;
                }
            }
            *shutdown_signal.lock().unwrap() = true;
        },
        _ = sigint.recv() => {
            warn!("A SIGINT was received. Exit the program...");
            *shutdown_signal.lock().unwrap() = true;
        },
        _ = sigquit.recv() => {
            info!("A SIGQUIT was received. Exit the program...");
            *shutdown_signal.lock().unwrap() = true;
        },
        _ = sigterm.recv() => {
            warn!("A SIGTERM was received. Exit the program...");
            *shutdown_signal.lock().unwrap() = true;
        }
    }

    // 全ての upstream 設定スレッドが完了するのを待つ
    let handles: Vec<_> = handles.lock().unwrap().drain(..).collect();
    for handle in handles {
        if let Err(e) = handle.await {
            error!("An error occurred in an upstream configuration thread: {}", e);
        }
    }
    eprintln!("all upstream configure threads are terminated");

    if let Err(e) = shutdown_nginx(nginx_pid) {
        eprintln!("fail to shutdown ngins: {}", e);
        std::process::exit(1);
    }
    // nginx プロセスの監視タスクが完了するのを待つ
    eprintln!("waiting for nginx process to terminate...");
    nginx_process.wait().await?;

    std::process::exit(exit_code);
}

fn update_ip_table(ip_addresses: &[IpAddr], ip_table: &mut Vec<IpEntry>) -> bool {
    let now = Instant::now();
    let mut changed = false;
    // ip_table に新しい IP アドレスを追加
    for ip in ip_addresses.iter() {
        if !ip_table.iter().any(|entry| entry.ip == *ip) {
            ip_table.push(IpEntry {
                ip: *ip,
                registered_at: now,
            });
            changed = true;
        }
    }
    // ip_table から ip_addresses に含まれない IP アドレスを削除
    let original_len = ip_table.len();
    ip_table.retain(|entry| ip_addresses.iter().all(|e| e != &entry.ip));
    if ip_table.len() != original_len {
        changed = true;
    }
    changed
}

fn start_nginx() -> Result<Child> {
    Command::new("nginx")
        .arg("-c")
        .arg("/etc/nginx/nginx.conf")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("nginx の起動に失敗しました")
}

fn reload_nginx(pid: Pid) -> Result<()> {
    kill(pid, Signal::SIGHUP).context("nginx のリロードに失敗しました")
}

fn shutdown_nginx(pid: Pid) -> Result<()> {
    kill(pid, Signal::SIGQUIT).context("nginx のシャットダウンに失敗しました")
}

fn create_upstream_config(
    upstream_name: &str,
    ips: &[IpEntry],
    port: Option<u16>,
    maxips: usize,
    config_dir: &Path,
) -> Result<()> {
    let config_path = config_dir.join(format!("{}.conf", upstream_name));
    let mut config_content = String::new();
    config_content.push_str(&format!("upstream {} {{\n", upstream_name));
    if ips.is_empty() {
        config_content.push_str("  server 127.0.0.1:10080;\n");
    } else {
        let mut sorted_ips = ips.to_vec();
        sorted_ips.sort_by(|a, b| b.registered_at.cmp(&a.registered_at));
        for ip_entry in sorted_ips.iter().take(maxips) {
            let server_line = match port {
                Some(p) => format!("  server {}:{};\n", ip_entry.ip, p),
                None => format!("  server {};\n", ip_entry.ip),
            };
            config_content.push_str(&server_line);
        }
    }
    config_content.push_str("}\n");
    fs::write(config_path, config_content).context("fail to update upstream configuration")
}
