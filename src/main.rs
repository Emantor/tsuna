use std::collections::HashMap;

use rpassword::prompt_password;
use reqwest;
use oo7;

use anyhow::{Result, Context, anyhow};

use serde::Deserialize;

#[derive(Default, Debug)]
struct Secrets {
    secret: String,
    device_id: String,
}

struct AppState<'a> {
    client: reqwest::Client,
    keyring: oo7::Keyring,
    secrets: Option<&'a Secrets>,
}

#[derive(Deserialize, Debug)]
struct POOCAPIResponse {
    status: i32,
    request: String,
    errors: Option<Vec<String>>,
    totp: Option<String>,
    email: Option<String>,
    secret: Option<String>,
    id: Option<String>,
}

#[derive(Deserialize, Debug)]
struct POMessage {
    id: i64,
    umid: i64,
    title: String,
    message: String,
    app: String,
    icon: String,
    date: i64,
    queued_date: i64,
    dispatched_date: i64,
    priority: i32,
    sound: String,
    url: String,
    url_title: String,
    acked: i32,
    receipt: i32,
    html: i32,
}

async fn prompt_user_password() -> Result<(String, String)> {
    println!("Username:");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    line = line.strip_suffix("\n").context("Couldn't strip newline from input, no input?")?.to_string();
    let password = prompt_password("Password: ")?;
    Ok((line, password))
}

async fn login(state: &AppState<'_>) -> Result<String> {
    let (user, password) = prompt_user_password().await?;
    let mut params = HashMap::new();
    params.insert("email", user);
    params.insert("password", password);

    let login_url = "https://api.pushover.net/1/users/login.json";
    let client = &state.client;
    let req = client.post(login_url).form(&params);
    println!("Sending request: {:?}", req);
    let res = req.send().await?;
    let status = res.status();
    let json: POOCAPIResponse = res.json().await?;
    match status {
        reqwest::StatusCode::PRECONDITION_FAILED => {
            assert!(json.status == 0);
            let mut token = String::new();
            println!("2FA Token:");
            std::io::stdin().read_line(&mut token)?;
            token = token.strip_suffix("\n").context("Couldn't strip newline from input, no input?")?.to_string();
            params.insert("twofa", token);
            let res = client.post(login_url).form(&params).send().await?;
            let status = res.status();
            let json: POOCAPIResponse = res.json().await?;
            match status {
                reqwest::StatusCode::OK => {
                    println!("debug: Json: {:?}", json);
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

async fn register_device(state: &AppState<'_>, secret: &str) -> Result<String> {
    let devices_url = "https://api.pushover.net/1/devices.json";
    let mut params = HashMap::new();
    let client = &state.client;

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

async fn get_secret_available(state: &AppState<'_>, tos: &str) -> Result<Option<String>> {
    let mut attributes = HashMap::new();
    attributes.insert("application", "tsuna");
    attributes.insert("type", tos);

    let items = state.keyring
        .search_items(attributes)
        .await?;

    if items.len() == 0 {
        return Ok(None);
    }
    Ok(Some(std::str::from_utf8(items[0].secret().await?.as_slice())?.to_string()))
}

async fn store_secrets(state: &AppState<'_>, secrets: &Secrets) -> Result<()> {
    let mut attributes = HashMap::new();
    attributes.insert("application", "tsuna");
    attributes.insert("type", "secret");

    state.keyring.create_item("Tsuna secret", attributes, secrets.secret.as_bytes(), true).await?;
    let mut attributes = HashMap::new();
    attributes.insert("application", "tsuna");
    attributes.insert("type", "device_id");
    state.keyring.create_item("Tsuna device_id", attributes, secrets.device_id.as_bytes(), true).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {

    let mut secrets = Secrets::default();

    let mut state = AppState {
        client: reqwest::Client::new(),
        keyring: oo7::Keyring::new().await?,
        secrets: None,
    };

    let sec_opt = get_secret_available(&state, "secret").await?;
    let dev_opt = get_secret_available(&state, "device_id").await?;

    if sec_opt == None || dev_opt == None {
        secrets.secret = login(&state).await?;
        secrets.device_id = register_device(&state, &&secrets.secret).await?;
        store_secrets(&state, &secrets).await?;
    } else {
        secrets.secret = sec_opt.unwrap();
        secrets.device_id = dev_opt.unwrap();
    }

    state.secrets = Some(&secrets);

    Ok(())
}
