use lambda_http::http::StatusCode;
use lambda_http::{Body, Response};
use thiserror::Error;
use serde_json::json;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid username or password")]
    InvalidCredentials,
    #[error("User not found")]
    UserNotFound,
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Internal server error: {0}")]
    Internal(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Please verify your email")]
    EmailNotVerified,
    #[error("Invalid email")]
    InvalidEmail,
    #[error("Invalid phone")]
    InvalidPhone,
    #[error("Credentials Validation failed")]
    CredentialsValidationFailed,
    #[error("Invalid full name")]
    InvalidFullName,
    #[error("Hashing error: {0}")]
    HashingError(String),
    #[error("Email already exists")]
    EmailAlreadyExists,
    #[error("Token not found")]
    TokenNotFound,
    #[error("Token expired")]
    TokenExpired,
}

impl AuthError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            AuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            AuthError::UserNotFound => StatusCode::NOT_FOUND,
            AuthError::UserAlreadyExists => StatusCode::CONFLICT,
            AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            AuthError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::ValidationError(_) => StatusCode::BAD_REQUEST,
            AuthError::EmailNotVerified => StatusCode::FORBIDDEN,
            AuthError::InvalidEmail => StatusCode::BAD_REQUEST,
            AuthError::InvalidPhone => StatusCode::BAD_REQUEST,
            AuthError::InvalidFullName => StatusCode::BAD_REQUEST,
            AuthError::HashingError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::CredentialsValidationFailed => StatusCode::BAD_REQUEST,
            AuthError::EmailAlreadyExists => StatusCode::CONFLICT,
            AuthError::TokenNotFound => StatusCode::NOT_FOUND,
            AuthError::TokenExpired => StatusCode::UNAUTHORIZED,
        }
    }

    pub fn to_response(&self) -> Response<Body> {
        Response::builder()
            .status(self.status_code())
            .header("Content-Type", "application/json")
            .body(Body::from(json!({
                "message": self.to_string()
            }).to_string()))
            .unwrap_or_else(|_| Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap())
    }
}

impl From<AuthError> for Response<Body> {
    fn from(error: AuthError) -> Self {
        error.to_response()
    }
}
