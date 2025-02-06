mod db;
mod email;
mod error;
mod jwt;
mod models;

use crate::db::DynamoDBServiceUser;
use crate::db::DynamoDBServiceUserTokens;
use crate::email::EmailService;
use crate::error::AuthError;
use crate::models::LoginRequest;
use crate::models::RegisterRequest;
use crate::models::ForgotPasswordRequest;
use crate::models::ChangePasswordRequest;
use crate::models::LogoutRequest;
use crate::models::UpdateProfileRequest;
use crate::models::VerifyRequest;
use crate::models::dbUser;
use crate::models::dbUserToken;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use aws_config::load_defaults;
use chrono::{DateTime, Utc};
use lambda_http::{
    http::{Response, StatusCode},
    run, service_fn, Body, Error, IntoResponse, Request, RequestPayloadExt,
};
use serde_json::json;
use std::collections::HashMap;
use std::env::var;

use rand::rngs::OsRng;
use tokio::task;

// Helper function to get IP from request
fn get_client_ip(event: &Request) -> String {
    event
        .headers()
        .get("X-Forwarded-For")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or("unknown")
        .to_string()
}

async fn handler(event: Request) -> Result<Response<Body>, Error> {
    let config: aws_config::SdkConfig = load_defaults(aws_config::BehaviorVersion::latest()).await;
    let dynamodb_client: aws_sdk_dynamodb::Client = aws_sdk_dynamodb::Client::new(&config);
    let ses_client = aws_sdk_ses::Client::new(&config);

    let user_table_name: String = match var("DYNAMODB_USER_TABLE_NAME") {
        Ok(name) => name,
        Err(_) => {
            tracing::error!("DYNAMODB_USER_TABLE_NAME environment variable not found");
            return Ok(AuthError::Internal("".to_string()).to_response());
        }
    };
    let token_table_name: String = match var("DYNAMODB_TABLE_NAME_TOKENS") {
        Ok(name) => name,
        Err(_) => {
            tracing::error!("DYNAMODB_TABLE_NAME_TOKENS environment variable not found");
            return Ok(AuthError::Internal("".to_string()).to_response());
        }
    };
    let from_email: String = match var("SES_FROM_EMAIL") {
        Ok(email) => email,
        Err(_) => {
            tracing::error!("SES_FROM_EMAIL environment variable not found");
            return Ok(AuthError::Internal("".to_string()).to_response());
        }
    };
    let db_service_user = DynamoDBServiceUser::new(dynamodb_client.clone(), user_table_name);
    let db_service_token = DynamoDBServiceUserTokens::new(dynamodb_client.clone(), token_table_name);
    let email_service = EmailService::new(ses_client, from_email);
    let path = event.uri().path();
    let method = event.method();
    //let query_params = event.uri().query().unwrap_or("");

    match (method.as_str(), path) {
        ("POST", "/dev/enter") => handle_login(event, &db_service_user, &db_service_token).await,
        ("POST", "/dev/register") => handle_register(event, &db_service_user, &email_service).await,
        ("POST", "/dev/verify") => handle_verify(event, &db_service_user, &db_service_token, &email_service).await,
        ("POST", "/dev/forgot-password") => handle_forgot_password(event, &db_service_user, &email_service).await,
        ("POST", "/dev/change-password") => handle_change_password(event, &db_service_user).await,
        ("POST", "/dev/logout") => handle_logout(event, &db_service_user).await,
        ("POST", "/dev/update-profile") => handle_update_profile(event, &db_service_user, &email_service).await,
        _ => Ok(Response::builder()
            .status(404)
            .body(Body::from("Not Found"))?),
    }
}

async fn handle_register(
    event: Request,
    db_service: &DynamoDBServiceUser,
    email_service: &EmailService,
) -> Result<Response<Body>, Error> {

    //this is to parse and validate the request body in json format
    let register_req: RegisterRequest = match event.payload::<RegisterRequest>() {
        Ok(Some(req)) => match RegisterRequest::new(req) {
            Ok(register_req) => register_req,
            Err(e) => {
                tracing::error!("Validation failed: {:?}", e);
                return Ok(e.to_response());
            }
        },
        Ok(None) => {
            tracing::error!("Empty request body");
            return Ok(AuthError::ValidationError("Empty request body".to_string()).to_response());
        }
        Err(e) => {
            tracing::error!("Invalid JSON format: {:?}", e);
            return Ok(
                AuthError::ValidationError("Invalid request format".to_string()).to_response(),
            );
        }
    };

    // Get client IP address from request
    let client_ip = get_client_ip(&event);

    //Check if user exists
    match db_service.check_user(&register_req.email).await {
        Ok(_) => (),
        Err(e) => {
            return Ok(e.to_response());
        }
    }

    // Hash password
    let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
    let password_hash =
        match Argon2::default().hash_password(register_req.password.as_bytes(), &salt) {
            Ok(hash) => hash.to_string(),
            Err(e) => {
                tracing::error!("Hashing error: {:?}", e);
                return Ok(AuthError::HashingError(e.to_string()).to_response());
            }
        };

    // Create user
    let user: dbUser = match db_service
        .create_user(
            &register_req.name,
            &register_req.email,
            &register_req.phone,
            &password_hash,
            &client_ip,
        )
        .await
    {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Failed to create user: {:?}", e);
            return Ok(e.to_response());
        }
    };

    // Send verification email
    // if let Some(token) = &user.verification_token {
    //     email_service.send_verification_email(&user.email, token).await?;
    // }

    Ok(Response::builder()
        .status(201)
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "message": "User created successfully. Please check your email to verify your account.",
            })
            .to_string(),
        ))?)
}

async fn handle_verify(
    event: Request,
    db_service: &DynamoDBServiceUser,
    db_service_token: &DynamoDBServiceUserTokens,
    email_service: &EmailService,

) -> Result<Response<Body>, Error> {
    let verify_req: VerifyRequest = match event.payload::<VerifyRequest>() {
        Ok(Some(req)) => match VerifyRequest::new(req) {
            Ok(verify_req) => verify_req,
            Err(e) => {
                return Ok(e.to_response());
            }
        },
        Ok(None) => {
            return Ok(AuthError::ValidationError("Empty request body".to_string()).to_response());
        },
        Err(e) => {
            return Ok(
                AuthError::ValidationError("Invalid request format".to_string()).to_response(),
            );
        }
    };

    // Check if token exists
    match db_service_token.get_user_token( &verify_req.token).await {
        Ok(_) => (),
        Err(e) => {
            return Ok(e.to_response());
        }
    }


    Ok(Response::builder()
        .status(200)
        .body(Body::from("Verify successful"))?)
}

async fn handle_forgot_password(
    event: Request,
    db_service: &DynamoDBServiceUser,
    email_service: &EmailService,
) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(200)
        .body(Body::from("Forgot password successful"))?)
}

async fn handle_change_password(
    event: Request,
    db_service: &DynamoDBServiceUser,
) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(200)
        .body(Body::from("Change password successful"))?)
}

async fn handle_logout(
    event: Request,
    db_service: &DynamoDBServiceUser,
) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(200)
        .body(Body::from("Logout successful"))?)
}

async fn handle_update_profile(
    event: Request,
    db_service: &DynamoDBServiceUser,
    email_service: &EmailService,
) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(200)
        .body(Body::from("Update profile successful"))?)
}

async fn handle_login(
    event: Request,
    db_service: &DynamoDBServiceUser,
    db_service_token: &DynamoDBServiceUserTokens,
) -> Result<Response<Body>, Error> {
    let login_req: LoginRequest = match event.payload::<LoginRequest>() {
        Ok(Some(req)) => match LoginRequest::new(req) {
            Ok(login_req) => login_req,
            Err(e) => {
                tracing::error!("Validation failed: {:?}", e);
                return Ok(e.to_response());
            }
        },
        Ok(None) => {
            tracing::error!("Empty request body");
            return Ok(AuthError::ValidationError("Empty request body".to_string()).to_response());
        }
        Err(e) => {
            tracing::error!("Invalid JSON format: {:?}", e);
            return Ok(
                AuthError::ValidationError("Invalid request format".to_string()).to_response(),
            );
        }
    };

    // Get user by email
    let user: dbUser = match db_service.get_user_by_email(&login_req.username).await {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Failed to get user by email: {:?}", e);
            return Ok(e.to_response());
        }
    };

    if user.verified == false {
        return Ok(AuthError::EmailNotVerified.to_response());
    }

    let ip = get_client_ip(&event);
    // Verify password with Argon2

    let stored_hash = user.password_hash.clone();
    let password = login_req.password.clone();

    let parsed_hash = argon2::password_hash::PasswordHash::new(&stored_hash)
        .map_err(|e| AuthError::HashingError(e.to_string()))?;

    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => (),
        Err(e) => {
            tracing::error!("Password verification failed: {:?}", e);
            return Ok(AuthError::InvalidCredentials.to_response());
        }
    }

    // Get IP address from request
    //let ip: String = get_client_ip(&event);

    // Update login info
    //db_service.update_login_info(&user.user_id, &ip).await?;

    // Generate JWT token
    let token = jwt::generate_token(&user.user_id).unwrap();

    // Create user token
    match db_service_token.create_user_token(&user.user_id, &token, &ip, &"access_token".to_string()).await {
        Ok(_) => (),
        Err(e) => {
            return Ok(e.to_response());
        }
    }

    Ok(Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "token": token,
                "user_id": user.user_id
            })
            .to_string(),
        ))?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::INFO)
        .init();

    run(service_fn(handler)).await
}
