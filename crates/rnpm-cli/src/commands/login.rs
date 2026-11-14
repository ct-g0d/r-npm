//! npm login/adduser, following npm's auth.js and npm-profile web/couch flows.
use super::client_helper::CommandClient;
use anyhow::Result;
use reqwest::{Method, StatusCode, Url};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;

#[derive(Debug)]
pub(crate) struct InputClosed;
impl std::fmt::Display for InputClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authentication input closed")
    }
}
impl std::error::Error for InputClosed {}

pub(super) fn prompt(label: &str, default: Option<&str>, password: bool) -> Result<String> {
    loop {
        print!("{label} ");
        if let Some(value) = default.filter(|v| !v.is_empty()) {
            if password {
                print!("(<default hidden>) ");
            } else {
                print!("({value}) ");
            }
        }
        std::io::stdout().flush()?;
        let _echo = password.then(EchoGuard::disable);
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line)? == 0 {
            return Err(InputClosed.into());
        }
        if password {
            println!();
        }
        let value = line.trim_end_matches(['\r', '\n']);
        let value = if value.is_empty() {
            default.unwrap_or_default()
        } else {
            value
        };
        if value.is_empty() {
            continue;
        }
        let warning = if label == "Username:" {
            if value != value.to_lowercase() {
                Some("Name must be lowercase")
            } else if !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b))
            {
                Some("Name may not contain non-url-safe chars")
            } else if value.starts_with('.') {
                Some("Name may not start with \".\"")
            } else if value.len() > 214 {
                Some("Name length must be less than or equal to 214 characters long")
            } else if value.contains('\'') {
                Some("Name may not contain illegal character \"'\"")
            } else {
                None
            }
        } else if label.starts_with("Email") {
            if value.len() > 254 {
                Some("Email length must be less then or equal to 254 characters long")
            } else if !value.split_once('@').is_some_and(|(a, b)| {
                !a.is_empty()
                    && b.split_once('.')
                        .is_some_and(|(c, d)| !c.is_empty() && !d.is_empty())
            }) {
                Some("Email must be an email address")
            } else {
                None
            }
        } else {
            None
        };
        if let Some(warning) = warning {
            eprintln!("npm warn {warning}");
            continue;
        }
        return Ok(if password {
            value.to_string()
        } else {
            value.trim().to_string()
        });
    }
}

// Preserve console settings even when a read fails. Pipe input has no echo mode.
struct EchoGuard {
    #[cfg(windows)]
    console: Option<(*mut std::ffi::c_void, u32)>,
    #[cfg(unix)]
    settings: Option<libc::termios>,
}
#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetStdHandle(kind: u32) -> *mut std::ffi::c_void;
    fn GetConsoleMode(handle: *mut std::ffi::c_void, mode: *mut u32) -> i32;
    fn SetConsoleMode(handle: *mut std::ffi::c_void, mode: u32) -> i32;
}
impl EchoGuard {
    fn disable() -> Self {
        #[cfg(windows)]
        unsafe {
            let handle = GetStdHandle(-10i32 as u32);
            let mut mode = 0;
            let console = (GetConsoleMode(handle, &mut mode) != 0
                && SetConsoleMode(handle, mode & !4) != 0)
                .then_some((handle, mode));
            Self { console }
        }
        #[cfg(unix)]
        unsafe {
            let mut mode = std::mem::zeroed();
            let settings = if libc::tcgetattr(0, &mut mode) == 0 {
                let mut hidden = mode;
                hidden.c_lflag &= !libc::ECHO;
                (libc::tcsetattr(0, libc::TCSANOW, &hidden) == 0).then_some(mode)
            } else {
                None
            };
            Self { settings }
        }
    }
}
impl Drop for EchoGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some((handle, mode)) = self.console {
            unsafe {
                SetConsoleMode(handle, mode);
            }
        }
        #[cfg(unix)]
        if let Some(mode) = &self.settings {
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, mode);
            }
        }
    }
}

async fn response_json(response: reqwest::Response, method: &str, target: &Url) -> Result<Value> {
    let status = response.status();
    let body: Value = response.json().await?;
    if !status.is_success() {
        let message = body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or_default();
        anyhow::bail!(
            "npm error code E{}\nnpm error {} {} - {method} {target} - {message}",
            status.as_u16(),
            status.as_u16(),
            status.canonical_reason().unwrap_or_default()
        );
    }
    Ok(body)
}

fn web_url(body: &Value, key: &str) -> Option<Url> {
    Url::parse(body.get(key)?.as_str()?)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))
}

pub(crate) fn open_auth_url(current_dir: &Path, title: &str, url: &Url) -> Result<()> {
    use std::io::IsTerminal;
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    if config.get_bool("json").unwrap_or(false) {
        println!("{}", serde_json::to_string_pretty(&json!({"title":title,"url":url.as_str()}))?);
    } else { println!("{title}:\n{url}"); }
    if config.get("browser") == Some("false") || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() { return Ok(()); }
    print!("Press ENTER to open in the browser...");
    std::io::stdout().flush()?;
    let browser = config.get("browser").filter(|v| *v != "true").map(str::to_string);
    let url = url.to_string();
    // Polling must continue while the opener waits, as npm-profile does.
    std::thread::spawn(move || {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() { return; }
        let mut command = if let Some(browser) = browser {
            std::process::Command::new(browser)
        } else if cfg!(windows) {
            let mut command = std::process::Command::new("rundll32.exe");
            command.arg("url.dll,FileProtocolHandler"); command
        } else { std::process::Command::new(if cfg!(target_os = "macos") { "open" } else { "xdg-open" }) };
        let _ = command.arg(url).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
    });
    Ok(())
}

async fn web_login(
    client: &CommandClient,
    adduser: bool,
    current_dir: &Path,
) -> Result<Option<Value>> {
    let target = Url::parse(&format!("{}-/v1/login", client.registry_url))?;
    let response = client
        .request(Method::POST, target.clone(), None)
        .json(&if adduser {
            json!({"create":true})
        } else {
            json!({})
        })
        .send()
        .await?;
    let status = response.status();
    if status.is_client_error() || status == StatusCode::INTERNAL_SERVER_ERROR {
        return Ok(None);
    }
    let body = response_json(response, "POST", &target).await?;
    let Some(login_url) = web_url(&body, "loginUrl") else {
        anyhow::bail!(
            "npm error code E{}\nnpm error Invalid response from web login endpoint",
            status.as_u16()
        );
    };
    let Some(mut done_url) = web_url(&body, "doneUrl") else {
        anyhow::bail!(
            "npm error code E{}\nnpm error Invalid response from web login endpoint",
            status.as_u16()
        );
    };
    if done_url.host_str() == Some("registry.npmjs.org") {
        done_url
            .set_scheme(client.registry_url.scheme())
            .map_err(|_| anyhow::anyhow!("Invalid registry scheme"))?;
        done_url.set_host(client.registry_url.host_str())?;
        done_url
            .set_port(client.registry_url.port())
            .map_err(|_| anyhow::anyhow!("Invalid registry port"))?;
        let prefix = client.registry_url.path().trim_end_matches('/');
        if !prefix.is_empty()
            && done_url.path() != prefix
            && !done_url.path().starts_with(&format!("{prefix}/"))
        {
            done_url.set_path(&format!("{prefix}{}", done_url.path()));
        }
    }
    open_auth_url(current_dir,
        if adduser {
            "Create your account at"
        } else {
            "Login at"
        }, &login_url
    )?;
    // Resolve auth for the poll URI, rather than sending registry credentials to an unrelated host.
    let poll_client = CommandClient::new(current_dir, Some(done_url.as_str()))?;
    loop {
        let response = poll_client
            .request(Method::GET, done_url.clone(), None)
            .send()
            .await?;
        let status = response.status();
        let retry = response
            .headers()
            .get("retry-after")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|s| s.is_finite() && *s > 0.0);
        let body = response_json(response, "GET", &done_url).await?;
        if status == StatusCode::OK
            && body
                .get("token")
                .is_some_and(|v| v.as_str().is_some_and(|s| !s.is_empty()))
        {
            return Ok(Some(body));
        }
        if status != StatusCode::ACCEPTED {
            anyhow::bail!(
                "npm error code E{}\nnpm error Invalid response from web login endpoint",
                status.as_u16()
            );
        }
        if let Some(seconds) = retry {
            tokio::time::sleep(std::time::Duration::from_secs_f64(seconds)).await;
        }
    }
}

pub(crate) async fn run(
    current_dir: &Path,
    registry: Option<String>,
    auth_type: Option<String>,
    scope: Option<String>,
    otp: Option<String>,
    adduser: bool,
) -> Result<()> {
    let config = rnpm_config::Config::load(Some(current_dir)).unwrap_or_default();
    let scope = scope
        .or_else(|| {
            config
                .get("scope")
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .map(|s| {
            if s.starts_with('@') {
                s
            } else {
                format!("@{s}")
            }
        });
    let registry = registry.or_else(|| {
        scope.as_ref().and_then(|s| {
            config
                .npmrc
                .scoped_registries
                .get(s)
                .map(ToString::to_string)
        })
    });
    let client = CommandClient::new(current_dir, registry.as_deref())?;
    let registry_url = &client.registry_url;
    if !client.silent {
        eprintln!("npm notice Log in on {registry_url}");
    }
    let auth_type = auth_type
        .or_else(|| config.get("auth-type").map(str::to_string))
        .unwrap_or_else(|| "web".into());
    let response = if auth_type == "web" {
        web_login(&client, adduser, current_dir).await?
    } else {
        None
    };
    let response = if let Some(response) = response {
        response
    } else {
        let key = super::logout::auth_key_for_registry(registry_url);
        let prefix = key.trim_end_matches("_authToken");
        let saved_user = config.npmrc.settings.get(&format!("{prefix}username"));
        let saved_password = config.npmrc.settings.get(&format!("{prefix}_password"))
            .and_then(|value| data_encoding::BASE64.decode(value.as_bytes()).ok())
            .and_then(|value| String::from_utf8(value).ok());
        let username = prompt("Username:", saved_user.map(String::as_str), false)?;
        let password = prompt("Password:", saved_password.as_deref(), true)?;
        let email = if adduser {
            Some(prompt(
                "Email (this will be public):",
                config.npmrc.settings.get(&format!("{prefix}email")).map(String::as_str).or_else(|| config.get("email")),
                false,
            )?)
        } else {
            None
        };
        let timestamp = crate::sbom::current_rfc3339_time().replace(
            'Z',
            &format!(
                ".{:03}Z",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_millis()
            ),
        );
        let mut body = json!({"_id":format!("org.couchdb.user:{username}"),"name":username,"password":password,"type":"user","roles":[],"date":timestamp});
        if let Some(email) = email {
            body["email"] = email.into();
        }
        let target = Url::parse(&format!("{registry_url}-/user/org.couchdb.user:{username}"))?;
        let response = client
            .request(Method::PUT, target.clone(), otp.as_deref())
            .json(&body)
            .send()
            .await?;
        if !adduser && response.status() == StatusCode::CONFLICT {
            let mut get_target = target.clone();
            get_target.set_query(Some("write=true"));
            let old = response_json(
                client
                    .request(Method::GET, get_target.clone(), otp.as_deref())
                    .send()
                    .await?,
                "GET",
                &get_target,
            )
            .await?;
            for (key, value) in old.as_object().into_iter().flatten() {
                if body
                    .get(key)
                    .is_none_or(|v| v.is_null() || v == false || v == "")
                    || key == "roles"
                {
                    body[key] = value.clone();
                }
            }
            let revision = body.get("_rev").and_then(Value::as_str).unwrap_or_default();
            let target = Url::parse(&format!("{target}/-rev/{revision}"))?;
            let response = client
                .client
                .put(target.clone())
                .basic_auth(&username, Some(&password))
                .json(&body);
            let response = if let Some(otp) = &otp {
                response.header("npm-otp", otp)
            } else {
                response
            };
            response_json(response.send().await?, "PUT", &target).await?
        } else if !adduser && response.status() == StatusCode::BAD_REQUEST {
            anyhow::bail!(
                "npm error code E400\nnpm error There is no user with the username \"{username}\"."
            );
        } else {
            response_json(response, "PUT", &target).await?
        }
    };
    let token = response
        .get("token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow::anyhow!("npm error No credentials to set."))?;
    let userconfig = rnpm_config::get_default_user_npmrc();
    let auth_key = super::logout::auth_key_for_registry(registry_url);
    let nerfed = auth_key.trim_end_matches("_authToken");
    if userconfig.exists() {
        if let Some(email) = config.npmrc.settings.get(&format!("{nerfed}email")) {
            rnpm_config::set_config_value_in_file(&userconfig, "email", email)?;
        }
        for key in [
            "_token".to_string(),
            format!("{nerfed}always-auth"),
            format!("{nerfed}email"),
            format!("{nerfed}_password"),
            format!("{nerfed}username"),
        ] {
            rnpm_config::delete_config_value_from_file(&userconfig, &key)?;
        }
    }
    rnpm_config::set_config_value_in_file(&userconfig, &auth_key, token)?;
    if let Some(scope) = &scope {
        rnpm_config::set_config_value_in_file(
            &userconfig,
            &format!("{scope}:registry"),
            registry_url.as_str(),
        )?;
    }
    println!(
        "Logged in{} on {registry_url}.",
        scope.map(|s| format!(" to scope {s}")).unwrap_or_default()
    );
    Ok(())
}
