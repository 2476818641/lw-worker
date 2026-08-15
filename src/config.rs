// 配置：命令行参数 + 可选配置文件 /etc/blackout-lw.conf

use std::env;
use std::fmt;

#[derive(Debug, Clone)]
pub struct Config {
    pub controller: String, // host:port（Controller HTTP 端口）
    pub token: String,      // worker token
    pub threads: u32,       // 攻击并发线程
    pub max_pps: u64,       // 节流上限（0 = 不限制）
    pub heartbeat_secs: u64,
    pub platform: String,   // 上报用平台标识
    pub arch: String,
}

#[derive(Debug)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Config {
    pub fn platform_name(&self) -> String {
        format!("{}-{}", self.platform, self.arch)
    }
}

pub fn load() -> Result<Config, ConfigError> {
    let args: Vec<String> = env::args().collect();
    let mut controller = String::new();
    let mut token = String::new();
    let mut threads: u32 = 8;
    let mut max_pps: u64 = 0;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" => {
                i += 1;
                controller = args.get(i).ok_or(ConfigError("missing value for -c".into()))?.clone();
            }
            "-t" => {
                i += 1;
                token = args.get(i).ok_or(ConfigError("missing value for -t".into()))?.clone();
            }
            "-threads" => {
                i += 1;
                threads = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or(ConfigError("invalid -threads".into()))?;
            }
            "-pps" => {
                i += 1;
                max_pps = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .ok_or(ConfigError("invalid -pps".into()))?;
            }
            other => return Err(ConfigError(format!("unknown argument: {other}"))),
        }
        i += 1;
    }

    if controller.is_empty() || token.is_empty() {
        return Err(ConfigError("controller and token are required".into()));
    }
    if threads == 0 || threads > 256 {
        return Err(ConfigError("threads must be 1-256".into()));
    }

    Ok(Config {
        controller,
        token,
        threads,
        max_pps,
        heartbeat_secs: 5,
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
    })
}
