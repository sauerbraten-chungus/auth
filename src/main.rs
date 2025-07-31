use std::{collections::HashSet, env};

use axum::{Router, extract::State, http::HeaderMap, routing::get};

#[derive(Clone)]
struct AppState {
    chungus_keys: HashSet<String>,
    secret_chungus: String,
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

async fn get_jwt(headers: HeaderMap, State(state): State<AppState>) {
    let api_key = headers
        .get("CHUNGUS-KEY")
        .and_then(|header_value| header_value.to_str().ok());

    if let Some(key) = api_key {
        if state.chungus_keys.contains(key) {
            // return JWT
        } else {
            // return epic fail
        }
    } else {
        // return epic fail
    }
}

fn generate_jwt() {}

fn load_api_keys() -> HashSet<String> {
    let mut api_keys = HashSet::new();
    for (key, value) in env::vars() {
        if key.starts_with("CHUNGUS_API_KEY_") {
            api_keys.insert(value);
        }
    }

    api_keys
}
