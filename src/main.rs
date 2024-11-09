use anyhow::{Result, anyhow};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_sts::Client as StsClient;
use aws_smithy_types_convert::date_time::DateTimeExt;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use clap::Parser;
use hyper::body::Incoming;
use http_body_util::Full;
use bytes::Bytes;
use hyper::{Request, Response};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Sha256, Digest};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use tokio::sync::OnceCell;
use url::Url;
use std::convert::Infallible;

#[derive(Debug, Serialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
}

#[derive(Clone)]
struct AuthConfig {
    client_id: String,
    auth_endpoint: String,
    token_endpoint: String,
    scope: String,
}

struct PkceParams {
    verifier: String,
    challenge: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    id_token: Option<String>,
    refresh_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcConfig {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    email: Option<String>,
    sub: String,
    exp: i64,
}

#[derive(Debug, Serialize)]
struct CredentialProcessOutput {
    Version: i32,
    AccessKeyId: String,
    SecretAccessKey: String,
    SessionToken: String,
    Expiration: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: DateTime<Utc>,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// OIDC Provider URL
    #[arg(long,short)]
    oidc_url: Option<String>,

    /// Auth endpoint (if not using OIDC URL)
    #[arg(long,short)]
    auth_endpoint: Option<String>,

    /// Token endpoint (if not using OIDC URL)
    #[arg(long,short)]
    token_endpoint: Option<String>,

    /// Client ID
    #[arg(long,short)]
    client_id: String,

    /// AWS Role ARN
    #[arg(long,short)]
    role_arn: String,

    /// Role session name (optional)
    #[arg(long)]
    role_session_name: Option<String>,

    /// Scope
    #[arg(long, default_value = "openid email")]
    scope: String,

    /// Do not write credentials to cache
    #[arg(long,short)]
    no_cache: bool,

    /// Bypass credential cache and force refresh
    #[arg(long,short)]
    force: bool,

    /// Output credential_process format
    #[arg(long)]
    creds_process: bool,
}

const SUCCESS_HTML: &str = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Authentication Successful</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }
        .message {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-radius: 50%;
            border-top: 3px solid #3498db;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            margin: 10px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="message">
        <h2>Authentication Successful!</h2>
        <p>You can return to the application.</p>
        <div class="spinner"></div>
    </div>
    <script>
        setTimeout(() => {
            window.close();
        }, 1500);
    </script>
</body>
</html>
"#;

impl AuthConfig {
    async fn from_args(args: &Args) -> Result<Self> {
        if let Some(oidc_url) = &args.oidc_url {
            let config_url = format!("{}/.well-known/openid-configuration", oidc_url.trim_end_matches('/'));
            let oidc_config: OidcConfig = reqwest::get(&config_url)
                .await?
                .json()
                .await?;

            Ok(Self {
                client_id: args.client_id.clone(),
                auth_endpoint: oidc_config.authorization_endpoint,
                token_endpoint: oidc_config.token_endpoint,
                scope: args.scope.clone(),
            })
        } else {
            let auth_endpoint = args.auth_endpoint
                .as_ref()
                .ok_or_else(|| anyhow!("auth_endpoint is required when oidc_url is not provided"))?;
            let token_endpoint = args.token_endpoint
                .as_ref()
                .ok_or_else(|| anyhow!("token_endpoint is required when oidc_url is not provided"))?;

            Ok(Self {
                client_id: args.client_id.clone(),
                auth_endpoint: auth_endpoint.clone(),
                token_endpoint: token_endpoint.clone(),
                scope: args.scope.clone(),
            })
        }
    }
}

impl PkceParams {
    fn new() -> Self {
        // Generate random verifier
        let mut rng = rand::thread_rng();
        let mut buffer = vec![0u8; 32];
        rng.fill_bytes(&mut buffer);
        let verifier = URL_SAFE_NO_PAD.encode(&buffer);

        // Create challenge
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        Self { verifier, challenge }
    }
}

async fn handle_callback(
    req: Request<Incoming>,
    auth_code: Arc<OnceCell<String>>,
    received: Arc<AtomicBool>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let uri = req.uri();
    let query = uri.query().unwrap_or("");
    let params: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();

    if let Some((_, code)) = params.iter().find(|(k, _)| k == "code") {
        auth_code.set(code.clone()).ok();
        received.store(true, Ordering::SeqCst);

        Ok(Response::builder()
            .status(200)
            .header("Content-Type", "text/html")
            .body(Full::new(Bytes::from(SUCCESS_HTML)))
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(400)
            .body(Full::new(Bytes::from("No authorization code received")))
            .unwrap())
    }
}

async fn perform_device_auth_flow(config: AuthConfig) -> Result<TokenResponse> {
    let pkce = PkceParams::new();
    let auth_code: Arc<OnceCell<String>> = Arc::new(OnceCell::new());
    let received = Arc::new(AtomicBool::new(false));

    // Setup local server
    let listener = TcpListener::bind("127.0.0.1:42069").await?;
    let auth_code_clone = auth_code.clone();
    let received_clone = received.clone();

    // Spawn the server task
    tokio::spawn(async move {
        loop {
            if received_clone.load(Ordering::SeqCst) {
                break;
            }

            if let Ok((stream, _)) = listener.accept().await {
                let io = TokioIo::new(stream);
                let auth_code = auth_code_clone.clone();
                let received = received_clone.clone();

                tokio::task::spawn(async move {
                    let service = hyper::service::service_fn(move |req| {
                        handle_callback(req, auth_code.clone(), received.clone())
                    });

                    if let Err(err) = http1::Builder::new()
                        .serve_connection(io, service)
                        .await
                    {
                        eprintln!("Error serving connection: {:?}", err);
                    }
                });
            }
        }
    });

    let redirect_uri = "http://localhost:42069/callback".to_string();

    // Construct authorization URL
    let auth_url = Url::parse_with_params(&config.auth_endpoint, &[
        ("client_id", config.client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("response_type", "code"),
        ("scope", config.scope.as_str()),
        ("code_challenge", pkce.challenge.as_str()),
        ("code_challenge_method", "S256"),
    ])?;

    webbrowser::open(auth_url.as_str())?;

    // Wait for the code
    while !received.load(Ordering::SeqCst) {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    // Add a small delay to ensure the success page is shown
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    let code = auth_code
        .get()
        .ok_or_else(|| anyhow!("No authorization code received"))?;

    // Exchange code for tokens
    let token_request = TokenRequest {
        grant_type: "authorization_code".to_string(),
        code: code.clone(),
        redirect_uri,
        client_id: config.client_id.clone(),
        code_verifier: pkce.verifier,
    };

    let client = reqwest::Client::new();
    let response = client
        .post(&config.token_endpoint)
        .form(&token_request)
        .send()
        .await?;

    let response_text = response.text().await?;
    let token_response: TokenResponse = serde_json::from_str(&response_text)?;

    Ok(token_response)
}

async fn get_aws_credentials(id_token: &str, role_arn: &str, session_name: &str) -> Result<CachedCredentials> {
    let region_provider = RegionProviderChain::default_provider();
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region_provider)
        .no_credentials()
        .load()
        .await;
    
    let sts_client = StsClient::new(&config);

    let response = sts_client
        .assume_role_with_web_identity()
        .role_arn(role_arn)
        .web_identity_token(id_token)
        .role_session_name(session_name)
        .send()
        .await?;

    let credentials = response.credentials()
        .ok_or_else(|| anyhow!("No credentials in response"))?;

    Ok(CachedCredentials {
        access_key_id: credentials.access_key_id().to_string(),
        secret_access_key: credentials.secret_access_key().to_string(),
        session_token: credentials.session_token().to_string(),
        expiration: credentials.expiration().to_chrono_utc().unwrap_or_else(|_| Utc::now() + chrono::Duration::hours(1)),
    })
}

fn get_cache_path() -> PathBuf {
    let mut path = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("oidc-cli");
    path.push("aws-credentials.json");
    path
}

fn load_cached_credentials() -> Option<CachedCredentials> {
    let path = get_cache_path();
    if !path.exists() {
        return None;
    }

    let contents = fs::read_to_string(path).ok()?;
    let creds: CachedCredentials = serde_json::from_str(&contents).ok()?;

    // Check if credentials are still valid (with 5 minute buffer)
    if creds.expiration > Utc::now() + chrono::Duration::minutes(5) {
        Some(creds)
    } else {
        None
    }
}

fn save_credentials(creds: &CachedCredentials) -> Result<()> {
    let path = get_cache_path();
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(path, serde_json::to_string_pretty(creds)?)?;
    Ok(())
}

fn extract_email_from_id_token(id_token: &str) -> Result<String> {
    // Split the JWT into parts
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err(anyhow!("Invalid JWT format"));
    }

    // Decode the payload (second part)
    let payload = URL_SAFE_NO_PAD.decode(parts[1])?;
    let payload_str = String::from_utf8(payload)?;
    let claims: Value = serde_json::from_str(&payload_str)?;

    // Try to get email or fall back to subject
    let email = claims.get("email")
        .and_then(|v| v.as_str())
        .or_else(|| claims.get("sub").and_then(|v| v.as_str()))
        .ok_or_else(|| anyhow!("No email or subject found in token"))?;

    Ok(email.to_string())
}

fn export_credentials(creds: &CachedCredentials) {
    println!("export AWS_ACCESS_KEY_ID={}", creds.access_key_id);
    println!("export AWS_SECRET_ACCESS_KEY={}", creds.secret_access_key);
    println!("export AWS_SESSION_TOKEN={}", creds.session_token);
}

fn output_credential_process(creds: &CachedCredentials) {
    let output = CredentialProcessOutput {
        Version: 1,
        AccessKeyId: creds.access_key_id.clone(),
        SecretAccessKey: creds.secret_access_key.clone(),
        SessionToken: creds.session_token.clone(),
        Expiration: creds.expiration.to_rfc3339(),
    };
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if !args.force {
        if let Some(cached_creds) = load_cached_credentials() {
            if args.creds_process {
                output_credential_process(&cached_creds);
            } else {
                export_credentials(&cached_creds);
            }
            return Ok(());
        }
    }

    let config = AuthConfig::from_args(&args).await?;
    let tokens = perform_device_auth_flow(config).await?;
    
    let id_token = tokens.id_token
        .ok_or_else(|| anyhow!("No ID token received. Ensure 'openid' is in your scope."))?;

    let session_name = args.role_session_name
        .unwrap_or_else(|| extract_email_from_id_token(&id_token)
            .unwrap_or_else(|_| "default-session".to_string()));

    let cached_creds = get_aws_credentials(&id_token, &args.role_arn, &session_name).await?;

    if !args.no_cache {
        save_credentials(&cached_creds)?;
    }

    if args.creds_process {
        output_credential_process(&cached_creds);
    } else {
        export_credentials(&cached_creds);
    }

    Ok(())
}