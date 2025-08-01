use std::{
    collections::HashSet,
    env,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;

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

    let state = AppState {
        chungus_keys: load_api_keys(),
        secret_chungus: env::var("SECRET_CHUNGUS").unwrap_or_else(|_| "".to_string()),
    };

    let app = Router::new()
        .route("/", get(|| async { "Hello World" }))
        .route("/auth", get(get_jwt))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8081")
        .await
        .unwrap();

    axum::serve(listener, app).await.unwrap();
}

async fn get_jwt(headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let api_key = headers
        .get("CHUNGUS-KEY")
        .and_then(|header_value| header_value.to_str().ok());

    match api_key {
        Some(key) if state.chungus_keys.contains(key) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize;

            let claims = Claims {
                exp: now + 3600,
                iat: now,
                sub: "kappapenis".to_string(),
            };

            match generate_jwt(&state.secret_chungus, &claims) {
                Ok(token) => (StatusCode::OK, token),
                Err(_) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to generate token".to_string(),
                ),
            }
        }
        Some(_) => (StatusCode::UNAUTHORIZED, "Invalid API Key".to_string()),
        None => (
            StatusCode::BAD_REQUEST,
            "Missing chungus header".to_string(),
        ),
    }
}

fn generate_jwt(secret: &str, claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    let header = Header::new(Algorithm::HS256);
    let encoding_key = EncodingKey::from_secret(secret.as_ref());

    encode(&header, &claims, &encoding_key)
}

fn load_api_keys() -> HashSet<String> {
    let mut api_keys = HashSet::new();
    for (key, value) in env::vars() {
        if key.starts_with("CHUNGUS_API_KEY_") {
            api_keys.insert(value);
        }
    }

    api_keys
}
