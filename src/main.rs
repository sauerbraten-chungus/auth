use std::{
    collections::HashSet,
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use serde_with::skip_serializing_none;
use tracing::{debug, error, info, warn};

#[derive(Serialize)]
#[skip_serializing_none]
struct AuthResponse {
    token: Option<String>,
    error: Option<String>,
}

#[derive(Clone)]
struct AppState {
    chungus_keys: HashSet<String>,
    secret_chungus: String,
}

#[derive(Serialize)]
struct Claims {
    exp: usize,
    iat: usize,
    sub: String,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_thread_ids(true)
        .init();

    let state = AppState {
        chungus_keys: load_api_keys(),
        secret_chungus: env::var("SECRET_CHUNGUS").unwrap_or_else(|_| "".to_string()),
    };
    info!("Loaded {} API Keys", state.chungus_keys.len());

    let app = Router::new()
        .route("/", get(|| async { "Hello World" }))
        .route("/auth", get(get_jwt))
        .with_state(state);

    let bind_addr = "127.0.0.1:8081";
    let listener = tokio::net::TcpListener::bind(bind_addr).await.unwrap();

    axum::serve(listener, app).await.unwrap();
    info!("Server started at {}", bind_addr);
}

async fn get_jwt(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let api_key = headers
        .get("CHUNGUS-KEY")
        .and_then(|header_value| header_value.to_str().ok());

    match api_key {
        Some(key) if state.chungus_keys.contains(key) => {
            info!("Valid API key provided, generating JWT");

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize;

            let expires_in = 3600; // 1 hour

            let claims = Claims {
                exp: now + expires_in,
                iat: now,
                sub: "kappapenis".to_string(),
            };

            match generate_jwt(&state.secret_chungus, &claims) {
                Ok(token) => {
                    info!("JWT generated successfully");
                    let response = AuthResponse {
                        token: Some(token),
                        error: None,
                    };
                    (StatusCode::OK, Json(response))
                }
                Err(e) => {
                    error!("Failed to generate JWT: {:?}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(AuthResponse {
                            token: None,
                            error: Some(e.to_string()),
                        }),
                    )
                }
            }
        }
        Some(_) => {
            warn!("Invalid API key attempted");
            (
                StatusCode::UNAUTHORIZED,
                Json(AuthResponse {
                    token: None,
                    error: Some("Invalid API Key".to_string()),
                }),
            )
        }
        None => {
            warn!("Request missing CHUNGUS-KEY header");
            (
                StatusCode::BAD_REQUEST,
                Json(AuthResponse {
                    token: None,
                    error: Some("Missing chungus header".to_string()),
                }),
            )
        }
    }
}

fn generate_jwt(secret: &str, claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    debug!(
        "Generating JWT with claims: sub={}, exp={}",
        claims.sub, claims.exp
    );
    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(secret.as_ref());

    encode(&header, &claims, &encoding_key)
}

fn load_api_keys() -> HashSet<String> {
    let mut api_keys = HashSet::new();
    for (key, value) in env::vars() {
        if key.starts_with("CHUNGUS_API_KEY_") {
            debug!("Loading API key: {}", key);
            api_keys.insert(value);
        }
    }

    api_keys
}
