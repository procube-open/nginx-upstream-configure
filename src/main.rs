use std::env;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use anyhow::{anyhow, Context, Result};
use log::{error, warn, info, debug, LevelFilter};
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::Deserialize;
use tokio::task::JoinHandle;
use tokio::signal::unix::{signal, SignalKind};
use tokio::process::{Child, Command};
use regex::Regex;
use futures::future::try_join_all;
use trust_dns_resolver::TokioAsyncResolver;
use env_logger::Builder as LoggerBuilder;
use chrono::{DateTime, Utc};

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
    registered_at: DateTime<Utc>,
}

fn get_env_var(key: &str, default: &str, pattern: &str) -> Result<String> {
    let value = env::var(key).unwrap_or_else(|_| default.to_string());
    let re = Regex::new(pattern).context("Regular expression compilation failed")?;
    if !re.is_match(&value) {
        return Err(anyhow!("Value '{}' of environment variable {} does not match pattern '{}'", value, key, pattern));
    }
    Ok(value)
}

fn get_env_var_as_u64(key: &str, default: &str, pattern: &str) -> Result<u64> {
    let value_str = get_env_var(key, default, pattern)?;
    value_str.parse::<u64>().context(format!("Cannot convert value '{}' of environment variable {} to a number", value_str, key))
}

#[tokio::main]
async fn main() -> Result<()> {
    // Config options from environment variables
    let upstreams_dir = get_env_var("UPSCONF_UPSTREAMS_DIR", "/etc/nginx/upstreams.d", r"^/[\w/.]+$")?;
    let nginx_conf_dir_str = get_env_var("UPSCONF_NGINX_CONF_DIR", "/etc/nginx/conf.d", r"^/[\w/.]+$")?;
    let nginx_conf_dir_str = Box::leak(Box::new(nginx_conf_dir_str));
    let nginx_conf_dir = Path::new(nginx_conf_dir_str);
    let ttl_on_fail = get_env_var_as_u64("UPSCONF_TTL_ON_FAIL", "30", r"^[\d]+$")?;
    let nginx_stable_millis = get_env_var_as_u64("UPSCONF_NGINX_STABLE_MILLIS", "1000", r"^[\d]+$")?;
    let nginx_conf = get_env_var("UPSCONF_NGINX_CONF", "/etc/nginx/nginx.conf", r"^/[\w/.]+\.conf$")?;
    let empty_server_conf = get_env_var("UPSCONF_EMPTY_SERVER_CONF", "127.0.0.1:10080", r"^[\d:.]+$")?;

    // Initialize logger
    let log_level = env::var("UPSCONF_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    LoggerBuilder::new()
        .filter_level(LevelFilter::Info)
        .parse_filters(&log_level)
        .init();

    // read upstream config files
    let mut upstream_configs = HashMap::new();
    for entry in fs::read_dir(upstreams_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("yml") {
            debug!("Load upstream config file: {}", path.display());
            let config_str = fs::read_to_string(&path)?;
            let config: UpstreamConfig = serde_yaml::from_str(&config_str)?;
            if upstream_configs.contains_key(&config.name) {
                return Err(anyhow!("Duplicate upstream name '{}'", config.name));
            }
            upstream_configs.insert(config.name.clone(), config);
        }
    }

    // initialize ip_table for each upstream
    let ip_tables: Arc<Mutex<HashMap<String, Vec<IpEntry>>>> = Arc::new(Mutex::new(HashMap::new()));

    // generate empty upstream configuration
    for (upstream_name, _) in upstream_configs.clone() {
        create_upstream_config(&upstream_name, &[], None, 0, empty_server_conf.clone(), nginx_conf_dir)?;
    }

    // start nginx and ensure it is running
    let mut nginx_process = start_nginx(nginx_conf)?;
    let nginx_pid = Pid::from_raw(nginx_process.id().unwrap() as i32);
    tokio::time::sleep(Duration::from_millis(nginx_stable_millis)).await;
    if let Some(status) = nginx_process.try_wait()? {
        return Err(anyhow!("nginx process exited immediately after starting: {:?}", status));
    }

    // Configure signal handler for graceful shutdown
    let shutdown_signal = Arc::new(Mutex::new(false));
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigquit = signal(SignalKind::quit())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    // Execute processing in parallel for each upstream configuration file
    let handles: Arc<Mutex<Vec<JoinHandle<Result<()>>>>> = Arc::new(Mutex::new(Vec::new()));
    for (upstream_name, config) in upstream_configs.clone() {
        let shutdown_signal = shutdown_signal.clone();
        ip_tables.lock().unwrap().insert(config.name.clone(), Vec::new());
        let ip_tables = ip_tables.clone();
        let empty_server_conf = empty_server_conf.clone();
        let handle: JoinHandle<Result<(), anyhow::Error>> = tokio::spawn(async move {
            info!(
                "spawn DNS Query thread fqdn={} for upstream '{}'",
                config.fqdn,
                upstream_name
            ); 
            // Configure DNS Resolver according to the contents of /etc/resolv.conf
            let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
            let mut ttl = Duration::from_secs(ttl_on_fail);
            loop {
                // Query the fqdn and update the upstream configuration file
                let mut ip_addresses = Vec::new();
                let empty_server_conf = empty_server_conf.clone();
                match resolver.lookup_ip(&config.fqdn).await {
                    Ok(response) => {
                        // The resolver itself has a caching function, so if you make a query without reaching the previous valid_until time,
                        // the cached result will be returned and the valid_until value will remain old. 
                        // In order to exceed valid_until with sleep,
                        // it seems that we can pass it to sleep as is as a Duration type without using as_secs etc.
                        let now = Instant::now();
                        let valid_until = response.valid_until();
                        if let Some(ttl_duration) = valid_until.checked_duration_since(now) {
                            ttl = ttl_duration;
                            debug!("query suceeded ttl={}mills", ttl.as_millis());
                        } else {
                            warn!("query suceeded, but valid_until is in the past, use priviues ttl={}millis", ttl.as_millis());
                        }
                        for record in response.iter() {
                            ip_addresses.push(record);
                        }
                        let mut my_ip_tables = ip_tables.lock().unwrap();
                        if let Some(ip_table) = my_ip_tables.get_mut(&upstream_name) {
                            debug!(
                                "Find out if we need to update upstream settings: ips={}", 
                                ip_addresses.iter().map(|ip| ip.to_string()).collect::<Vec<String>>().join(", "));
                            if update_ip_table(&ip_addresses, ip_table) {
                                info!(
                                    "There was a change in the upstream server addresses: ips={} ttl={}millis",
                                    ip_table
                                        .iter()
                                        .map(|entry| format!("ip={} registeredAt={}", entry.ip, entry.registered_at.to_rfc3339()))
                                        .collect::<Vec<String>>()
                                        .join(", "),
                                    ttl.as_millis()
                                );
                                create_upstream_config(
                                    &upstream_name,
                                    ip_table,
                                    config.port,
                                    config.maxips,
                                    empty_server_conf,
                                    nginx_conf_dir,
                                )?;
                                reload_nginx(nginx_pid)?;
                            } else {
                                debug!("No change in the upstream server addresses");
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "fail to DNS Query fqdn={} for upstream {}, so clear ip table and configure upstream to return errors : {}",
                            config.fqdn, upstream_name, e
                        );
                        ttl = Duration::from_secs(ttl_on_fail);
                        let mut my_ip_tables = ip_tables.lock().unwrap();
                        let ip_table = my_ip_tables.get_mut(&upstream_name).unwrap();
                        ip_table.clear();
                        create_upstream_config(
                            &upstream_name,
                            &[],
                            None,
                            config.maxips,
                            empty_server_conf,
                            nginx_conf_dir
                        )?;
                        reload_nginx(nginx_pid)?;
                    }
                }

                // sleep until the IP address's TTL expires or a shutdown signal is received
                tokio::select! {
                    _ = tokio::time::sleep(ttl) => {
                        debug!("wake up from {} milli seconds sleeping", ttl.as_millis());
                    },
                    true = async {
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

    info!("upstream configuration threads are started");
    // Wait until one of the upstream configuration tasks finishes,
    // the nginx process exits, or a shutdown signal is received
    let mut exit_code = 0;
    tokio::select! {
        result = try_join_all(handles.lock().unwrap().drain(..)) => {
            if let Err(e) = result {
                error!("An error occurred in the upstream configuration thread: {}", e);
                exit_code = 1;
            } else {
                debug!("a upstream configure thread is terminated");
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
            warn!("A SIGINT was received. Exit the program...waiting for all threads and nginx to terminate");
            *shutdown_signal.lock().unwrap() = true;
        },
        _ = sigquit.recv() => {
            info!("A SIGQUIT was received. Exit the program...waiting for all threads and nginx to terminate");
            *shutdown_signal.lock().unwrap() = true;
        },
        _ = sigterm.recv() => {
            warn!("A SIGTERM was received. Exit immediately");
            std::process::exit(1);
        }
    }

    // Wait for all upstream configuration tasks to complete
    let handles: Vec<_> = handles.lock().unwrap().drain(..).collect();
    for handle in handles {
        if let Err(e) = handle.await {
            error!("An error occurred in an upstream configuration thread: {}", e);
        }
    }
    info!("all upstream configure threads are terminated");

    if let Err(e) = shutdown_nginx(nginx_pid) {
        error!("fail to shutdown ngins: {}", e);
        std::process::exit(1);
    }
    // Wait for nginx process monitoring task to complete
    nginx_process.wait().await?;
    info!("nginx process is terminated");

    std::process::exit(exit_code);
}

fn update_ip_table(ip_addresses: &[IpAddr], ip_table: &mut Vec<IpEntry>) -> bool {
    let mut changed = false;
    // ip_table に新しい IP アドレスを追加
    for ip in ip_addresses.iter() {
        if ip_table.iter().all(|entry| entry.ip != *ip) {
            info!("add new IP address: {}", ip);
            ip_table.push(IpEntry {
                ip: *ip,
                registered_at: Utc::now(),
            });
            changed = true;
        }
    }
    // Remove IP addresses not included in ip_addresses from ip_table
    ip_table.retain(|entry| {
        if ip_addresses.iter().all(|e| e != &entry.ip) {
            info!("remove IP address: {}", entry.ip);
            changed = true;
            false
        } else {
            true
        }
    });
    changed
}

fn start_nginx(nginx_conf: String) -> Result<Child> {
    Command::new("nginx")
        .arg("-c")
        .arg(nginx_conf)
        .arg("-g")
        .arg("daemon off;")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .context("Failed to start nginx")
}

fn reload_nginx(pid: Pid) -> Result<()> {
    kill(pid, Signal::SIGHUP).context("Failed to reload nginx")
}

fn shutdown_nginx(pid: Pid) -> Result<()> {
    kill(pid, Signal::SIGQUIT).context("Failed to shutdown nginx")
}

fn create_upstream_config(
    upstream_name: &str,
    ips: &[IpEntry],
    port: Option<u16>,
    maxips: usize,
    empty_server_conf: String,
    config_dir: &Path,
) -> Result<()> {
    let config_path = config_dir.join(format!("{}.conf", upstream_name));
    let mut config_content = String::new();
    config_content.push_str(&format!("upstream {} {{\n", upstream_name));
    if ips.is_empty() {
        debug!("No IP address is available for upstream '{}'. Use empty server configuration", upstream_name);
        config_content.push_str(&format!("  server {};\n", empty_server_conf));
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
    fs::write(config_path, config_content).context("fail to update upstream configuration")?;
    Ok(())
}
