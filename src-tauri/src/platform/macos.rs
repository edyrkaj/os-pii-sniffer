use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyStatus {
    pub enabled: bool,
    pub server: String,
    pub port: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedProxy {
    pub service: String,
    pub web: ProxyStatus,
    pub secure: ProxyStatus,
    pub bypass: Vec<String>,
}

pub fn beep() {
    let _ = Command::new("afplay")
        .arg("/System/Library/Sounds/Ping.aiff")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

pub fn process_name(client: SocketAddr) -> String {
    let needle = format!(":{}->", client.port());
    let output = Command::new("lsof")
        .args(["-nP", "-iTCP", &format!(":{}", client.port())])
        .output();
    let Ok(output) = output else {
        return "unknown".to_string();
    };
    if !output.status.success() {
        return "unknown".to_string();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let own_pid = std::process::id().to_string();
    for line in text.lines().skip(1) {
        let mut columns = line.split_whitespace();
        let Some(command) = columns.next() else {
            continue;
        };
        let Some(pid) = columns.next() else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        if line.contains(&needle) {
            return command.to_string();
        }
    }
    "unknown".to_string()
}

pub fn cert_is_trusted(cert_path: &Path) -> bool {
    if Command::new("security")
        .args(["verify-cert", "-p", "basic", "-c"])
        .arg(cert_path)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
    {
        return true;
    }
    Command::new("security")
        .args(["dump-trust-settings", "-d"])
        .output()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout).contains("PII Sniffer Local CA")
                || String::from_utf8_lossy(&output.stderr).contains("PII Sniffer Local CA")
        })
        .unwrap_or(false)
}

pub fn ensure_trusted(cert_path: &Path) -> Result<(), String> {
    if cert_is_trusted(cert_path) {
        return Ok(());
    }
    let status = Command::new("security")
        .args(["add-trusted-cert", "-d", "-r", "trustRoot", "-k"])
        .arg(login_keychain())
        .arg(cert_path)
        .status()
        .map_err(|error| format!("Could not start Keychain trust prompt: {error}"))?;
    if !status.success() {
        return Err("macOS did not trust the local certificate. Protection stays off.".to_string());
    }
    Ok(())
}

pub fn active_service() -> Result<String, String> {
    let route = run_command("route", &["-n", "get", "default"])?;
    let interface = parse_route_interface(&route).unwrap_or_default();
    let ports = run_command("networksetup", &["-listallhardwareports"])?;
    if let Some(service) = parse_hardware_ports(&ports)
        .into_iter()
        .find(|(_, device)| device == &interface)
        .map(|(service, _)| service)
    {
        return Ok(service);
    }
    let services = run_command("networksetup", &["-listallnetworkservices"])?;
    parse_enabled_services(&services)
        .into_iter()
        .next()
        .ok_or_else(|| "No active network service found.".to_string())
}

pub fn install_proxy(port: u16) -> Result<SavedProxy, String> {
    let service = active_service()?;
    let saved = read_saved(&service)?;
    if let Err(error) = apply_proxy(&service, port, &saved) {
        let _ = restore_proxy(&saved);
        return Err(error);
    }
    Ok(saved)
}

fn apply_proxy(service: &str, port: u16, saved: &SavedProxy) -> Result<(), String> {
    let port_text = port.to_string();
    run_command(
        "networksetup",
        &["-setwebproxy", service, "127.0.0.1", &port_text],
    )?;
    run_command(
        "networksetup",
        &["-setsecurewebproxy", service, "127.0.0.1", &port_text],
    )?;
    run_command("networksetup", &["-setwebproxystate", service, "on"])?;
    run_command("networksetup", &["-setsecurewebproxystate", service, "on"])?;
    let mut bypass = saved.bypass.clone();
    for domain in ["localhost", "127.0.0.1", "*.local"] {
        if !bypass.iter().any(|item| item == domain) {
            bypass.push(domain.to_string());
        }
    }
    let mut args = vec!["-setproxybypassdomains".to_string(), service.to_string()];
    args.extend(bypass);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_command("networksetup", &arg_refs)?;
    Ok(())
}

pub fn restore_proxy(saved: &SavedProxy) -> Result<(), String> {
    restore_one(
        &saved.service,
        "-setwebproxy",
        "-setwebproxystate",
        &saved.web,
    )?;
    restore_one(
        &saved.service,
        "-setsecurewebproxy",
        "-setsecurewebproxystate",
        &saved.secure,
    )?;
    if saved.bypass.is_empty() {
        run_command(
            "networksetup",
            &["-setproxybypassdomains", &saved.service, "Empty"],
        )?;
    } else {
        let mut args = vec!["-setproxybypassdomains".to_string(), saved.service.clone()];
        args.extend(saved.bypass.iter().cloned());
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run_command("networksetup", &arg_refs)?;
    }
    Ok(())
}

fn restore_one(
    service: &str,
    set_cmd: &str,
    state_cmd: &str,
    status: &ProxyStatus,
) -> Result<(), String> {
    if status.enabled && !status.server.is_empty() && status.port != "0" {
        run_command(
            "networksetup",
            &[set_cmd, service, &status.server, &status.port],
        )?;
        run_command("networksetup", &[state_cmd, service, "on"])?;
    } else {
        run_command("networksetup", &[state_cmd, service, "off"])?;
    }
    Ok(())
}

fn read_saved(service: &str) -> Result<SavedProxy, String> {
    let web = parse_proxy_status(&run_command("networksetup", &["-getwebproxy", service])?);
    let secure = parse_proxy_status(&run_command(
        "networksetup",
        &["-getsecurewebproxy", service],
    )?);
    let bypass_text = run_command("networksetup", &["-getproxybypassdomains", service])?;
    Ok(SavedProxy {
        service: service.to_string(),
        web,
        secure,
        bypass: parse_bypass_domains(&bypass_text),
    })
}

pub fn parse_proxy_status(text: &str) -> ProxyStatus {
    let mut status = ProxyStatus {
        enabled: false,
        server: String::new(),
        port: "0".to_string(),
    };
    for line in text.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "Enabled" => status.enabled = value.eq_ignore_ascii_case("yes"),
                "Server" => status.server = value.to_string(),
                "Port" => status.port = value.to_string(),
                _ => {}
            }
        }
    }
    status
}

pub fn parse_route_interface(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("interface:") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub fn parse_hardware_ports(text: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("Hardware Port:") {
            current = Some(name.trim().to_string());
        } else if let Some(device) = line.strip_prefix("Device:")
            && let Some(name) = current.take()
        {
            pairs.push((name, device.trim().to_string()));
        }
    }
    pairs
}

pub fn parse_enabled_services(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("An asterisk"))
        .filter(|line| !line.starts_with('*'))
        .map(str::to_string)
        .collect()
}

pub fn parse_bypass_domains(text: &str) -> Vec<String> {
    if text.to_ascii_lowercase().contains("aren't any bypass")
        || text.to_ascii_lowercase().contains("there aren't")
    {
        return Vec::new();
    }
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect()
}

fn login_keychain() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users".to_string());
    format!("{home}/Library/Keychains/login.keychain-db")
}

fn run_command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("Could not run {program}: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!("{program} failed: {stderr}{stdout}")
            .trim()
            .to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_networksetup_text() {
        let status = parse_proxy_status(
            "Enabled: Yes\nServer: 127.0.0.1\nPort: 8765\nAuthenticated Proxy Enabled: 0\n",
        );
        assert!(status.enabled);
        assert_eq!(status.server, "127.0.0.1");
        assert_eq!(status.port, "8765");

        assert_eq!(
            parse_route_interface("   interface: en0\n").as_deref(),
            Some("en0")
        );
        let ports = parse_hardware_ports("Hardware Port: Wi-Fi\nDevice: en0\n");
        assert_eq!(ports, vec![("Wi-Fi".to_string(), "en0".to_string())]);
        let services = parse_enabled_services(
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bridge\n",
        );
        assert_eq!(services, vec!["Wi-Fi".to_string()]);
        assert!(parse_bypass_domains("There aren't any bypass domains set on Wi-Fi.").is_empty());
    }
}
