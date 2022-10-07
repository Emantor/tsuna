use std::collections::HashMap;

use rpassword::prompt_password;

use std::io::Write;

extern crate clap;
use clap::{Parser, Subcommand};

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

#[derive(Debug, Subcommand, PartialEq)]
enum Commands {
    /// Register as a new device with pushover
    Register,
    /// Delete existing credentials
    Delete,
    /// Download and delete messages
    Download,
}

use anyhow::{Result, Context, anyhow};

use serde::Deserialize;
use notify_rust::Notification;

#[derive(Debug)]
struct Secrets {
    keyring: oo7::Keyring,
    secret: String,
    device_id: String,
}

struct AppState<'a> {
    client: reqwest::Client,
    secrets: Option<&'a Secrets>,
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
}

async fn prompt_user_password() -> Result<(String, String)> {
    print!("Username:");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    line = line.strip_suffix("\n").context("Couldn't strip newline from input, no input?")?.to_string();
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
                token = token.strip_suffix("\n").context("Couldn't strip newline from input, no input?")?.to_string();
                params.insert("twofa", token);
                let res = client.post(login_url).form(&params).send().await?;
                let status = res.status();
                let json: POOCAPIResponse = res.json().await?;
                match status {
                    reqwest::StatusCode::OK => {
                        Ok(json.secret.unwrap())
                    }
                    _ => return Err(anyhow!("Unhandled status code from Open Client API"))
                }
            }
            reqwest::StatusCode::OK => {
                assert!(json.status == 1);
                Ok(json.secret.unwrap())
            }
            _ => {
                assert!(json.status == 0);
                return Err(anyhow!("Unhandled status code from Open Client API: {:?}", json))
            }
        }
    }

    async fn register_device(&self, secret: &str) -> Result<String> {
        let devices_url = "https://api.pushover.net/1/devices.json";
        let mut params = HashMap::new();
        let client = &self.client;

        params.insert("secret", secret.to_string());
        params.insert("os", "O".to_string());

        println!("Device name:");
        let mut name = String::new();
        std::io::stdin().read_line(&mut name)?;
        name = name.strip_suffix("\n").context("Couldn't strip newline from input, no input?")?.to_string();

        params.insert("name", name);

        let req = client.post(devices_url).form(&params);
        println!("Sending request: {:?}", req);
        let res = req.send().await?;
        let status = res.status();
        let json: POOCAPIResponse = res.json().await?;
        match status {
            reqwest::StatusCode::OK => {
                assert!(json.status == 1);
                Ok(json.id.unwrap().to_string())
            }
            _ => {
                assert!(json.status == 0);
                return Err(anyhow!("Unhandled status code from Open Client API: {:?}", json))
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
        println!("Response: {:?}", res);
        let json: POOCAPIResponse = res.json().await?;
        assert!(json.status == 1);
        let messages = json.messages.context("Messages Key not found in API response")?;
        match messages.len() {
            0 => return Ok(None),
            _ => return Ok(Some(messages)),
        }
    }

    async fn delete_messages(&self, messages: &Vec<POMessage>) -> Result<()> {
        let device_id = &self.secrets.context("Could not retrieve secrets from storage")?.device_id;
        let delete_url = format!("https://api.pushover.net/1/devices/{device_id}/update_highest_message.json");
        let mut params = HashMap::new();
        let client = &self.client;
        let secrets = &self.secrets.context("Could not load secret from storage")?;
        let max = messages.iter().fold(0, |max, x| if x.id > max { return x.id } else { max }).to_string();

        params.insert("secret", &secrets.secret);
        params.insert("message", &max);

        let res = client.post(delete_url).form(&params).send().await?;
        let json: POOCAPIResponse = res.json().await?;
        assert!(json.status == 1);

        return Ok(());
    }
}

impl Secrets {

    async fn get_secret_available(&self, tos: &str) -> Result<Option<String>> {
        let mut attributes = HashMap::new();
        attributes.insert("application", "tsuna");
        attributes.insert("type", tos);

        let items = self.keyring
            .search_items(attributes)
            .await?;

        if items.len() == 0 {
            return Ok(None);
        }
        Ok(Some(std::str::from_utf8(items[0].secret().await?.as_slice())?.to_string()))
    }

    async fn store_secrets(&self) -> Result<()> {
        let mut attributes = HashMap::new();
        attributes.insert("application", "tsuna");
        attributes.insert("type", "secret");

        self.keyring.create_item("Tsuna secret", attributes, self.secret.as_bytes(), true).await?;
        let mut attributes = HashMap::new();
        attributes.insert("application", "tsuna");
        attributes.insert("type", "device_id");
        self.keyring.create_item("Tsuna device_id", attributes, self.device_id.as_bytes(), true).await?;

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
        return Ok(Self {
            keyring: oo7::Keyring::new().await?,
            secret: String::default(),
            device_id: String::default(),
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {

    let args = Cli::parse();

    let mut secrets = Secrets::new().await?;

    let mut state = AppState {
        client: reqwest::Client::builder().user_agent(APP_USER_AGENT).build()?,
        secrets: None,
    };

    if args.command == Commands::Register {
            let sec_opt = secrets.get_secret_available("secret").await?;
            let dev_opt = secrets.get_secret_available("device_id").await?;
            if sec_opt != None || dev_opt != None {
                print!("Device already registered, please explictly delete with 'delete'");
                return Ok(());
            }
            secrets.secret = state.login().await?;
            secrets.device_id = state.register_device(&&secrets.secret).await?;
            secrets.store_secrets().await?;
            return Ok(());
    }

    let sec_opt = secrets.get_secret_available("secret").await?;
    let dev_opt = secrets.get_secret_available("device_id").await?;

    if sec_opt == None || dev_opt == None {
        println!("Please use the register command to register the device first.");
        return Ok(());
    } else {
        secrets.secret = sec_opt.unwrap();
        secrets.device_id = dev_opt.unwrap();
    }
    state.secrets = Some(&secrets);

    match args.command {
        Commands::Delete => {
            return secrets.delete_secrets().await;
        },
        Commands::Download => {

            let messages = state.download_messages().await?;

            match messages {
                Some(ref m) => {
                    for message in m {
                        Notification::new().summary(&message.title)
                                           .body(&message.message).show()?;
                    }
                },
                None => {},
            }

            if let Some(m) = &messages {
                state.delete_messages(m).await?;
            }


            Ok(())
        },
        Commands::Register => return Ok(()),

    }


}
