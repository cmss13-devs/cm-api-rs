use std::error::Error;

use crate::Config;

#[derive(Debug)]
struct LogError;

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Logging not set up.")
    }
}

impl Error for LogError {}

#[derive(serde::Serialize)]
struct ExternalLogAuthor {
    name: String,
    url: String,
}

#[derive(serde::Serialize)]
struct ExternalLogEmbed {
    title: String,
    description: String,
    color: i32,
    author: ExternalLogAuthor,
}

#[derive(serde::Serialize)]
struct ExternalLog {
    embeds: Vec<ExternalLogEmbed>,
    username: String,
}

pub async fn log_external(
    config: &Config,
    title: String,
    message: String,
) -> Result<(), Box<dyn Error>> {
    let logging_config = match &config.logging {
        Some(logging) => logging,
        None => return Err(Box::new(LogError {})),
    };

    let json = ExternalLog {
        embeds: vec![ExternalLogEmbed {
            title: title,
            description: message,
            color: 8359053,
            author: ExternalLogAuthor {
                name: "[cmdb]".to_string(),
                url: "https://db.cm-ss13.com".to_string(),
            },
        }],
        username: "[cmdb]".to_string(),
    };

    match reqwest::Client::new()
        .post(&logging_config.webhook)
        .body(serde_json::to_string(&json)?)
        .header("Content-Type", "application/json")
        .send()
        .await
    {
        Ok(_) => Ok(()),
        Err(err) => panic!("{err:?}"),
    }
}
