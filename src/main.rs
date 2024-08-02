use std::{collections::HashMap, time::Duration};

use rpassword::prompt_password;
use tokio::{io::AsyncWriteExt, time::error::Elapsed};

use std::io::Write;

extern crate clap;
use clap::{Parser, Subcommand};

use async_tungstenite::tokio::connect_async;
use async_tungstenite::tungstenite::protocol::Message;
use futures::prelude::*;
use tokio::time::{sleep, timeout};

use thiserror::Error;

static APP_USER_AGENT: &str = concat!(
    env!("CARGO_PKG_NAME"),
    "/",
    env!("CARGO_PKG_VERSION"),
    " (github.com/Emantor/tsuna)"
);

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Error, Debug)]
pub enum TsunaLoopError {
    #[error("Abort received while connected, re-registration required.")]
    Abort(),
    #[error("Generic error, will trigger a reconnection.")]
    Error(),
}

#[derive(Debug, Subcommand, PartialEq)]
enum Commands {
    /// Register as a new device with pushover
    Register,
    /// Delete existing credentials
    Delete,
    /// Download and delete messages
    Download,
    /// Start a Websocket and loop until canceled
    Loop,
}

use anyhow::{anyhow, Context, Result};

use notify_rust::Notification;
use serde::Deserialize;

#[derive(Debug)]
struct Secrets {
    keyring: oo7::Keyring,
    secret: String,
    device_id: String,
}

struct AppState<'a> {
    client: reqwest::Client,
    secrets: Option<&'a Secrets>,
    backoff_time: Duration,
    xdg_dirs: xdg::BaseDirectories,
}

#[derive(Deserialize, Debug)]
struct POOCAPIResponse {
    status: i32,
    secret: Option<String>,
    id: Option<String>,
    messages: Option<Vec<POMessage>>,
}

#[derive(Deserialize, Debug, Default)]
struct POMessage {
    id: i64,
    title: String,
    message: String,
    icon: String,
    priority: i64,
}

async fn prompt_user_password() -> Result<(String, String)> {
    print!("Username:");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    line = line
        .strip_suffix('\n')
        .context("Couldn't strip newline from input, no input?")?
        .to_string();
    let password = prompt_password("Password: ")?;
    Ok((line, password))
}

impl AppState<'_> {
    async fn login(&self) -> Result<String> {
        let (user, password) = prompt_user_password().await?;
        let mut params = HashMap::new();
        params.insert("email", user);
        params.insert("password", password);

        let login_url = "https://api.pushover.net/1/users/login.json";
        let client = &self.client;
        let req = client.post(login_url).form(&params);
        let res = req.send().await?;
        let status = res.status();
        let json: POOCAPIResponse = res.json().await?;
        match status {
            reqwest::StatusCode::PRECONDITION_FAILED => {
                assert!(json.status == 0);
                let mut token = String::new();
                print!("2FA Token:");
                std::io::stdout().flush()?;
                std::io::stdin().read_line(&mut token)?;
                token = token
                    .strip_suffix('\n')
                    .context("Couldn't strip newline from input, no input?")?
                    .to_string();
                params.insert("twofa", token);
                let res = client.post(login_url).form(&params).send().await?;
                let status = res.status();
                let json: POOCAPIResponse = res.json().await?;
                match status {
                    reqwest::StatusCode::OK => Ok(json.secret.unwrap()),
                    _ => Err(anyhow!("Unhandled status code from Open Client API")),
                }
            }
            reqwest::StatusCode::OK => {
                assert!(json.status == 1);
                Ok(json.secret.unwrap())
            }
            _ => {
                assert!(json.status == 0);
                Err(anyhow!(
                    "Unhandled status code from Open Client API: {:?}",
                    json
                ))
            }
        }
    }

    async fn register_device(&self, secret: &str) -> Result<String> {
        let devices_url = "https://api.pushover.net/1/devices.json";
        let mut params = HashMap::new();
        let client = &self.client;

        params.insert("secret", secret.to_string());
        params.insert("os", "O".to_string());

        print!("Device name:");
        std::io::stdout().flush()?;
        let mut name = String::new();
        std::io::stdin().read_line(&mut name)?;
        name = name
            .strip_suffix('\n')
            .context("Couldn't strip newline from input, no input?")?
            .to_string();

        params.insert("name", name);

        let req = client.post(devices_url).form(&params);
        log::debug!("Sending request: {:?}", req);
        let res = req.send().await?;
        let status = res.status();
        let json: POOCAPIResponse = res.json().await?;
        match status {
            reqwest::StatusCode::OK => {
                assert!(json.status == 1);
                Ok(json.id.unwrap())
            }
            _ => {
                assert!(json.status == 0);
                Err(anyhow!(
                    "Unhandled status code from Open Client API: {:?}",
                    json
                ))
            }
        }
    }

    async fn download_messages(&self) -> Result<Option<Vec<POMessage>>> {
        let download_url = "https://api.pushover.net/1/messages.json";
        let mut params = HashMap::new();
        let client = &self.client;
        let secrets = &self.secrets.context("Could not load secret from storage")?;
        params.insert("secret", &secrets.secret);
        params.insert("device_id", &secrets.device_id);
        let res = client.get(download_url).form(&params).send().await?;
        let json: POOCAPIResponse = res.json().await?;
        assert!(json.status == 1);
        let messages = json
            .messages
            .context("Messages Key not found in API response")?;
        match messages.len() {
            0 => Ok(None),
            _ => Ok(Some(messages)),
        }
    }

    async fn delete_messages(&self, messages: &[POMessage]) -> Result<()> {
        let device_id = &self
            .secrets
            .context("Could not retrieve secrets from storage")?
            .device_id;
        let delete_url =
            format!("https://api.pushover.net/1/devices/{device_id}/update_highest_message.json");
        let mut params = HashMap::new();
        let client = &self.client;
        let secrets = &self.secrets.context("Could not load secret from storage")?;
        let max = messages
            .iter()
            .fold(0, |max, x| if x.id > max { x.id } else { max })
            .to_string();

        params.insert("secret", &secrets.secret);
        params.insert("message", &max);

        let res = client.post(delete_url).form(&params).send().await?;
        let json: POOCAPIResponse = res.json().await?;
        assert!(json.status == 1);

        Ok(())
    }

    fn increment_backoff(&mut self) {
        if self.backoff_time.as_secs() < 60 {
            self.backoff_time += Duration::from_secs(10);
        }
    }

    fn reset_backoff(&mut self) {
        self.backoff_time = Duration::from_secs(10);
    }

    async fn get_icon(&self, icon: &str) -> Result<String> {
        let path = self.xdg_dirs.get_cache_file(format!("{icon}.png"));
        match path.exists() {
            true => Ok(path
                .into_os_string()
                .into_string()
                .expect("Path conv failed")),
            false => self.fetch_icon(icon).await,
        }
    }

    async fn fetch_icon(&self, icon: &str) -> Result<String> {
        let client = &self.client;
        let icon_url = format!("https://api.pushover.net/icons/{icon}.png");
        let res = client.get(icon_url).send().await?;
        assert!(res.status() == 200);
        let bytes = res.bytes().await?;
        let cache_name = self
            .xdg_dirs
            .place_cache_file(format!("{icon}.png"))
            .context("Could not create cache directory")?;
        let mut cache_file = tokio::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(false)
            .write(true)
            .open(&cache_name)
            .await?;
        cache_file.write_all(&bytes).await?;

        let filename = cache_name
            .into_os_string()
            .into_string()
            .expect("Icon conversion failed");

        Ok(filename)
    }
}

impl Secrets {
    async fn get_secret_available(&self, tos: &str) -> Result<Option<String>> {
        let mut attributes = HashMap::new();
        attributes.insert("application", "tsuna");
        attributes.insert("type", tos);

        let items = self.keyring.search_items(attributes).await?;

        if items.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            std::str::from_utf8(items[0].secret().await?.as_slice())?.to_string(),
        ))
    }

    async fn store_secrets(&self) -> Result<()> {
        let mut attributes = HashMap::new();
        attributes.insert("application", "tsuna");
        attributes.insert("type", "secret");

        self.keyring
            .create_item("Tsuna secret", attributes, self.secret.as_bytes(), true)
            .await?;
        let mut attributes = HashMap::new();
        attributes.insert("application", "tsuna");
        attributes.insert("type", "device_id");
        self.keyring
            .create_item(
                "Tsuna device_id",
                attributes,
                self.device_id.as_bytes(),
                true,
            )
            .await?;

        Ok(())
    }

    async fn delete_secrets(&self) -> Result<()> {
        let mut attributes = HashMap::new();
        attributes.insert("application", "tsuna");
        attributes.insert("type", "secret");

        self.keyring.delete(attributes).await?;

        let mut attributes = HashMap::new();
        attributes.insert("application", "tsuna");
        attributes.insert("type", "device_id");

        self.keyring.delete(attributes).await?;
        Ok(())
    }

    async fn new() -> Result<Self> {
        Ok(Self {
            keyring: oo7::Keyring::new().await?,
            secret: String::default(),
            device_id: String::default(),
        })
    }
}

const WS_URL: &str = "wss://client.pushover.net/push";

async fn display_message(state: &AppState<'_>, message: &POMessage) -> Result<()> {
    if message.priority < 0 {
        println!("{}: {}", message.title, message.message);
        return Ok(())
    }

    Notification::new()
        .summary(&message.title)
        .body(&message.message)
        .icon(&state.get_icon(&message.icon).await?)
        .show_async()
        .await?;
    Ok(())
}

async fn inner_loop(state: &mut AppState<'_>) -> Result<()> {
    let (mut ws_stream, _) = connect_async(WS_URL).await?;
    let secrets = state.secrets.context("No secrets loaded from backend")?;
    let login_text = format!("login:{}:{}\n", secrets.device_id, secrets.secret);

    ws_stream.send(Message::Text(login_text)).await?;

    state.reset_backoff();

    let (_write, mut read) = ws_stream.split();

    loop {
        let message = timeout(std::time::Duration::from_secs(95), read.next())
            .await?
            .unwrap()?;
        let text = message.to_text()?;
        match text {
            "!" => {
                while let Some(m) = state.download_messages().await? {

                    for message in &m {
                        display_message(state, message).await?;
                    }
                    state.delete_messages(&m).await?;
                }
            }
            "E" => {
                log::error!("Received an error from upstream, should reconnect");
                return Err(TsunaLoopError::Error().into());
            }
            "A" => {
                log::error!("Abort");
                return Err(TsunaLoopError::Abort().into());
            }
            "#" => {
                log::debug!("[{:?}], Keepalive", std::time::SystemTime::now());
            }
            _ => {}
        }
    }
}

async fn run_loop(state: &mut AppState<'_>) -> Result<()> {
    loop {
        match inner_loop(state).await {
            Err(ref e) if e.is::<Elapsed>() => {
                log::debug!("Read timeout, restarting loop");
                continue;
            }
            Err(ref e) if e.is::<std::io::Error>() => {
                sleep(state.backoff_time).await;
                state.increment_backoff();
                continue;
            }
            Err(e) if e.is::<TsunaLoopError>() => match e.downcast_ref::<TsunaLoopError>().unwrap()
            {
                TsunaLoopError::Abort() => return Err(e),
                TsunaLoopError::Error() => continue,
            },
            Ok(o) => return Ok(o),
            Err(e) => {
                log::info!("Got unhandled Error: {:?}, continuing", e);
                sleep(state.backoff_time).await;
                state.increment_backoff();
                continue;
            }
        };
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let args = Cli::parse();

    let mut secrets = Secrets::new().await?;

    let mut state = AppState {
        client: reqwest::Client::builder()
            .user_agent(APP_USER_AGENT)
            .build()?,
        secrets: None,
        backoff_time: Duration::from_secs(10),
        xdg_dirs: xdg::BaseDirectories::with_prefix("tsuna").unwrap(),
    };

    if args.command == Commands::Register {
        let sec_opt = secrets.get_secret_available("secret").await?;
        let dev_opt = secrets.get_secret_available("device_id").await?;
        if sec_opt.is_some() || dev_opt.is_some() {
            print!("Device already registered, please explictly delete with 'delete'");
            return Ok(());
        }
        secrets.secret = state.login().await?;
        secrets.device_id = state.register_device(&secrets.secret).await?;
        secrets.store_secrets().await?;
        return Ok(());
    }

    let sec_opt = secrets.get_secret_available("secret").await?;
    let dev_opt = secrets.get_secret_available("device_id").await?;

    if let (Some(sec_opt), Some(dev_opt)) = (sec_opt, dev_opt) {
        secrets.secret = sec_opt;
        secrets.device_id = dev_opt;
    } else {
        println!("Please use the register command to register the device first.");
        return Ok(());
    }
    state.secrets = Some(&secrets);

    match args.command {
        Commands::Delete => secrets.delete_secrets().await,
        Commands::Download => {
            let messages = state.download_messages().await?;

            if let Some(m) = &messages {
                for message in m {
                    display_message(&state, message).await?;
                }
                state.delete_messages(m).await?;
            }

            Ok(())
        }
        Commands::Register => Ok(()),
        Commands::Loop => run_loop(&mut state).await,
    }
}
