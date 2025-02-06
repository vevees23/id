use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use crate::error::AuthError;

const JWT_SECRET: &[u8] = b"Sainath.3"; // In production, use AWS Secrets Manager

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,  // user_id
    pub exp: i64,     // expiration time
    pub iat: i64,     // issued at
}

pub fn generate_token(user_id: &str) -> Result<String, AuthError> {
    let now = Utc::now();
    let expires_at = now + Duration::hours(24);
    
    let claims = Claims {
        sub: user_id.to_string(),
        exp: expires_at.timestamp(),
        iat: now.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET),
    )
    .map_err(|e| AuthError::Internal(e.to_string()))
}