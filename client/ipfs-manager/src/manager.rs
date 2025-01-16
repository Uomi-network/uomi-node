use std::process::{Command, Child, Stdio};
use std::sync::Arc;
use parking_lot::Mutex;
use log::{info, error};
use std::fs;
use tempfile::{TempPath, TempDir};
use std::io::{BufReader, BufRead};
use std::thread;
use regex::Regex;

pub struct IpfsManager {
    process: Arc<Mutex<Option<Child>>>,
    ipfs_path: TempPath,
    repo_dir: TempDir,  
}

impl IpfsManager {
    
    pub fn new() -> Result<Self, std::io::Error> {
        let temp_file = tempfile::NamedTempFile::new()?;
    
        // Determina il binario corretto basato su OS e architettura
        let ipfs_bytes: Vec<u8> = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("macos", _) => {
                log::info!("🌐 OS: macOS");
                include_bytes!(concat!(env!("OUT_DIR"), "/ipfs_macOS")).to_vec()
            },
            ("linux", "x86_64") => {
                log::info!("🌐 OS: Linux (amd64)");
                include_bytes!(concat!(env!("OUT_DIR"), "/ipfs_linux_amd64")).to_vec()
            },
            ("linux", "aarch64") => {
                log::info!("🌐 OS: Linux (arm64)");
                include_bytes!(concat!(env!("OUT_DIR"), "/ipfs_linux_arm64")).to_vec()
            },
            (os, arch) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Unsupported platform: OS={}, architecture={}", os, arch)
                ));
            }
        };
    
        fs::write(&temp_file, ipfs_bytes)?;
    
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = temp_file.as_file().metadata()?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(temp_file.path(), perms)?;
        }
    
        let ipfs_path = temp_file.into_temp_path();
        let repo_dir = TempDir::new()?;
    
        Ok(Self {
            process: Arc::new(Mutex::new(None)),
            ipfs_path,
            repo_dir,
        })
    }

    pub fn start_daemon(&self) -> Result<(), std::io::Error> {
        let mut process = self.process.lock();
        if process.is_none() {
            info!("🌐 Starting IPFS daemon...");
    
            self.init_repo()?;
    
            let mut child = Command::new(self.ipfs_path.to_path_buf())
                .arg("daemon")
                .env("IPFS_PATH", self.repo_dir.path())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
    
            let stdout = child.stdout.take().expect("Failed to capture stdout");
            let stderr = child.stderr.take().expect("Failed to capture stderr");
    
            let peer_id_regex = Regex::new(r"PeerID: (.+)").unwrap();
            let mut peer_id = None;
    
            // Leggi l'output in background
            let stdout_thread = std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    if let Ok(line) = line {
                        if line.contains("Daemon is ready") {
                            info!("🌐 IPFS daemon is ready");
                            break;
                        }
                        if let Some(captures) = peer_id_regex.captures(&line) {
                            peer_id = Some(captures[1].to_string());
                            info!("🌐 IPFS Peer ID: {}", peer_id.as_ref().unwrap());
                        }
                        if line.contains("error") || line.contains("fatal") {
                            error!("🌐 IPFS error: {}", line);
                        }
                    }
                }
            });
    
            let _= thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines() {
                    if let Ok(line) = line {
                        if line.contains("error") || line.contains("fatal") {
                            error!("🌐 IPFS error: {}", line);
                        }
                    }
                }
            });
    
            *process = Some(child);
    
            stdout_thread.join().expect("Failed to join stdout thread");
    
        } else {
            info!("🌐 IPFS daemon is already running.");
        }
        Ok(())
    }

    fn init_repo(&self) -> Result<(), std::io::Error> {
        let output = Command::new(self.ipfs_path.to_path_buf())
            .arg("init")
            .env("IPFS_PATH", self.repo_dir.path())
            .output()?;
    
        if output.status.success() {
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("ipfs configuration file already exists") {
                info!("🌐 IPFS repository already initialized");
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("🌐 Failed to initialize IPFS repo: {}", stderr)
                ));
            }
        }
        Ok(())
    }

    

    pub fn stop_daemon(&self) -> Result<(), std::io::Error> {
        let mut process = self.process.lock();
        if let Some(mut child) = process.take() {
            info!("🌐 Stopping IPFS daemon...");
            child.kill()?;
            child.wait()?;
            info!("🌐 IPFS daemon stopped successfully.");
        } else {
            info!("🌐 IPFS daemon is not running.");
        }
        Ok(())
    }
}

impl Drop for IpfsManager {
    fn drop(&mut self) {
        if let Err(e) = self.stop_daemon() {
            error!("Failed to stop IPFS daemon: {}", e);
        }
    }
}