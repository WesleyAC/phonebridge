#[macro_use]
extern crate lazy_static;

use warp::Filter;

use lettre::Transport;

use sha1::Sha1;
use hmac::{Hmac, Mac, NewMac};

use itertools::Itertools;

use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};

struct Config {
    port: u16,
    twilio_auth_token: String,
    mount_location: String,
}

fn load_config() -> Option<Config> {
    let mut file = File::open("config.toml").ok()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).ok()?;
    let config = contents.parse::<toml::Value>().ok()?.try_into::<toml::value::Table>().ok()?;

    let port = config.get("port").cloned()?.try_into::<i64>().ok()? as u16;
    let twilio_auth_token = config.get("twilio_auth_token").cloned()?.try_into::<String>().ok()?;
    let mount_location = config.get("mount_location").cloned()?.try_into::<String>().ok()?;

    Some(Config {
        port,
        twilio_auth_token,
        mount_location,
    })
}

lazy_static! {
    static ref CONFIG: Config = load_config().unwrap();
}

#[derive(Default)]
struct Stats {
    failed_emails: usize,
    failed_signatures: usize,
}

fn verify_twilio_signature(signature: &String, path: &String, request: &HashMap<String, String>) -> bool {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_varkey(CONFIG.twilio_auth_token.as_bytes()).unwrap();

    mac.update(CONFIG.mount_location.as_bytes());
    mac.update(path.as_bytes());

    for key in request.keys().sorted() {
        mac.update(key.as_bytes());
        mac.update(request[key].as_bytes());
    }

    let result = Vec::from(mac.finalize().into_bytes().as_slice());
    let signature = base64::decode(signature).unwrap();

    result == signature
}

fn send_email(subject: String, from_full: String, from_stripped: String, body: String) -> Result<(), lettre::transport::sendmail::Error> {
    let email = lettre::Message::builder()
        .from(format!("{} (via Phone Bridge) <phonebridge@hack.wesleyac.com>", from_full).parse().unwrap())
        .reply_to(format!("Phone Bridge <phonebridge+{}@hack.wesleyac.com>", from_stripped).parse().unwrap()) //TODO: make replies work
        .to("Wesley Aptekar-Cassels <me@wesleyac.com>".parse().unwrap())
        .subject(subject)
        .body(body)
        .unwrap();

    let transport = lettre::SendmailTransport::new();

    transport.send(&email)
}

#[tokio::main]
async fn main() {
    let stats = Arc::new(Mutex::new(Stats::default()));

    let incoming_sms_stats = stats.clone();
    let incoming_sms = warp::post()
        .and(warp::path!("incoming_sms"))
        .and(warp::body::form())
        .and(warp::header::<String>("X-Twilio-Signature"))
        .map(move |sms: HashMap<String, String>, signature: String| {
            if verify_twilio_signature(&signature, &"incoming_sms".to_string(), &sms) {
                let from_full = sms.get("From").unwrap().clone();
                let from_stripped: String = from_full.chars().filter(|c| c.is_digit(10)).collect();
                let mut body: String = sms.get("Body").unwrap().clone();
                body.push_str(&format!("\n\n{:?}", sms));

                if send_email("New SMS".to_string(), from_full, from_stripped, body).is_err() {
                    incoming_sms_stats.lock().unwrap().failed_emails += 1;
                }
            } else {
                incoming_sms_stats.lock().unwrap().failed_signatures += 1;
            }
            "<Response></Response>\n"
        })
        .with(warp::reply::with::header("Content-Type", "text/xml"));

    let recording_status_stats = stats.clone();
    let recording_status = warp::post()
        .and(warp::path!("recording_status"))
        .and(warp::body::form())
        .and(warp::header::<String>("X-Twilio-Signature"))
        .map(move |recording: HashMap<String, String>, signature: String| {
            if verify_twilio_signature(&signature, &"recording_status".to_string(), &recording) {
                // TODO: make this email a little nicer on the eye
                if send_email("New voicemail".to_string(), "voicemail".to_string(), "voicemail".to_string(), format!("{:?}", recording)).is_err() {
                    recording_status_stats.lock().unwrap().failed_emails += 1;
                }
            } else {
                recording_status_stats.lock().unwrap().failed_signatures += 1;
            }
            ""
        });

    let transcription_status_stats = stats.clone();
    let transcription_status = warp::post()
        .and(warp::path!("transcription_status"))
        .and(warp::body::form())
        .and(warp::header::<String>("X-Twilio-Signature"))
        .map(move |transcription: HashMap<String, String>, signature: String| {
            if verify_twilio_signature(&signature, &"transcription_status".to_string(), &transcription) {
                // TODO: fetch and parse transcription, put in email body.
                if send_email("Voicemail transcription".to_string(), "voicemail".to_string(), "voicemail".to_string(), format!("{:?}", transcription)).is_err() {
                    transcription_status_stats.lock().unwrap().failed_emails += 1;
                }
            } else {
                transcription_status_stats.lock().unwrap().failed_signatures += 1;
            }
            ""
        });

    let healthcheck_stats = stats.clone();
    let healthcheck = warp::get()
        .and(warp::path!("healthcheck"))
        .map(move || {
            let stats = healthcheck_stats.lock().unwrap();
            format!("alive\nfailed_emails: {}\nfailed_signatures: {}\n", stats.failed_emails, stats.failed_signatures)
        });

    let routes = healthcheck
        .or(incoming_sms)
        .or(recording_status)
        .or(transcription_status);

    warp::serve(routes)
        .run(([127, 0, 0, 1], CONFIG.port))
        .await;
}
