mod db;
mod email;
mod error;
mod jwt;
mod models;

use crate::db::DynamoDBServiceUser;
use crate::db::DynamoDBServiceUserAuthTokens;
use crate::db::DynamoDBServiceUserTokens;
use crate::email::EmailService;
use crate::error::AuthError;
use crate::models::dbUser;
use crate::models::dbUserToken;
use crate::models::ChangePasswordRequest;
use crate::models::ForgotPasswordRequest;
use crate::models::LoginRequest;
use crate::models::LogoutRequest;
use crate::models::RegisterRequest;
use crate::models::UpdateProfileRequest;
use crate::models::VerifyRequest;
use crate::models::TokenType;
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
    let auth_token_table_name: String = match var("DYNAMODB_TABLE_NAME_AUTH_TOKENS") {
        Ok(name) => name,
        Err(_) => {
            tracing::error!("DYNAMODB_TABLE_NAME_AUTH_TOKENS environment variable not found");
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
    let db_service_user_token =
        DynamoDBServiceUserTokens::new(dynamodb_client.clone(), token_table_name.clone());
    let db_service_auth_token =
        DynamoDBServiceUserAuthTokens::new(dynamodb_client.clone(), auth_token_table_name);
    let email_service = EmailService::new(ses_client, from_email);
    let path = event.uri().path();
    let method = event.method();
    //let query_params = event.uri().query().unwrap_or("");

    match (method.as_str(), path) {
        ("POST", "/dev/enter") => {
            handle_login(event, &db_service_user, &db_service_auth_token).await
        }
        ("POST", "/dev/register") => handle_register(event, &db_service_user, &db_service_user_token, &email_service).await,
        ("POST", "/dev/verify") => {
            handle_verify(
                event,
                &db_service_user,
                &db_service_user_token,
                &email_service,
            )
            .await
        }
        ("POST", "/dev/forgot-password") => {
            handle_forgot_password(event, &db_service_user, &email_service).await
        }
        ("POST", "/dev/change-password") => handle_change_password(event, &db_service_user).await,
        ("POST", "/dev/logout") => handle_logout(event, &db_service_user).await,
        ("POST", "/dev/update-profile") => {
            handle_update_profile(event, &db_service_user, &email_service).await
        }
        ("POST", "/dev/check") => {
            handle_check(
                event,
                &db_service_user,
                &db_service_user_token,
                &email_service,
            )
            .await
        }
        ("POST", "/dev/refresh") => {
            handle_refresh(event, &db_service_user, &db_service_auth_token).await
        }
        ("POST", "/dev/profile") => handle_profile(event, &db_service_auth_token).await,
        _ => Ok(Response::builder()
            .status(404)
            .body(Body::from("Not Found"))?),
    }
}

async fn handle_check(
    _event: Request,
    _db_service: &DynamoDBServiceUser,
    _db_service_token: &DynamoDBServiceUserTokens,
    _email_service: &EmailService,
) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(501)
        .body(Body::from("Not Implemented: Check"))?)
}

async fn handle_refresh(
    _event: Request,
    _db_service: &DynamoDBServiceUser,
    _db_service_auth_token: &DynamoDBServiceUserAuthTokens,
) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(501)
        .body(Body::from("Not Implemented: Refresh"))?)
}

async fn handle_profile(
    _event: Request,
    _db_service_auth_token: &DynamoDBServiceUserAuthTokens,
) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(501)
        .body(Body::from("Not Implemented: Profile"))?)
}

async fn handle_register(
    event: Request,
    db_service: &DynamoDBServiceUser,
    db_service_user_token: &DynamoDBServiceUserTokens,
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
    let user_id = match db_service
        .create_user(
            &register_req.name,
            &register_req.email,
            &register_req.phone,
            &password_hash,
            &client_ip,

        )
        .await
    {
        Ok(user_id) => user_id,
        Err(e) => {
            tracing::error!("Failed to create user: {:?}", e);
            return Ok(e.to_response());
        }
    };

    
    // Create verification token
    match db_service_user_token.create_user_token(&user_id, &TokenType::VerifyEmail, &client_ip).await {
        Ok(token) => {
            // Send verification email
            //email_service.send_verification_email(&register_req.email, &token).await?;
        }
        Err(e) => {
            tracing::error!("Failed to create user token: {:?}", e);
            return Ok(e.to_response());
        }
    }

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
        }
        Err(e) => {
            return Ok(
                AuthError::ValidationError("Invalid request format".to_string()).to_response(),
            );
        }
    };

    // Get client IP address from request
    let client_ip = get_client_ip(&event);

    // Check if token exists
    let token_data: dbUserToken = match db_service_token.get_user_token(&verify_req.token).await {
        Ok(token_data) => token_data,
        Err(e) => {
            return Ok(e.to_response()); // Token not found or other error
        }
    };

    if token_data.used {
        return Ok(AuthError::TokenExpired.to_response());
    }

    if token_data.expires_at < Utc::now() {
        return Ok(AuthError::TokenExpired.to_response());
    }
    
    let user_uuid: String = db_service.get_user_by_id(&token_data.user_id).await.unwrap();

    

    // Update user verification status
    match db_service
        .update_user_verified_status(&user_uuid, &client_ip)
        .await
    {
        Ok(_) => (),
        Err(e) => {
            tracing::error!("Failed to update user verification status: {:?}", e);
            return Ok(e.to_response()); // Database error
        }
    }

    match db_service_token.mark_token_used(&verify_req.token, &client_ip).await {
        Ok(_) => (),
        Err(e) => {
            tracing::error!("Failed to mark token as used: {:?}", e);
            return Ok(e.to_response()); // Database error
        }
    }


    Ok(Response::builder()
        .status(200)
        .body(Body::from("Email verified successfully"))?)
}

async fn handle_forgot_password(
    event: Request,
    db_service: &DynamoDBServiceUser,
    email_service: &EmailService,
) -> Result<Response<Body>, Error> {
    let forgot_password_req: ForgotPasswordRequest = match event.payload::<ForgotPasswordRequest>()
    {
        Ok(Some(req)) => match ForgotPasswordRequest::new(req) {
            Ok(forgot_password_req) => forgot_password_req,
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

    // Check if user exists
    let user: dbUser = match db_service
        .get_user_by_email(&forgot_password_req.email)
        .await
    {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Failed to get user by email: {:?}", e);
            return Ok(e.to_response());
        }
    };

    // Generate reset password token
    let reset_password_token = jwt::generate_token(&user.user_id).unwrap();

    // Store reset password token in db -  You might want to store this in a dedicated table for reset tokens with expiry
    
    // For simplicity, we are skipping this step for now and directly sending the token in email

    // // Send forgot password email
    // email_service
    //     .send_forgot_password_email(&user.email, &reset_password_token)
    //     .await?;

    Ok(Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(Body::from(
            json!({
                "message": "Password reset link sent to your email.",
            })
            .to_string(),
        ))?)
}

async fn handle_change_password(
    event: Request,
    db_service: &DynamoDBServiceUser,
) -> Result<Response<Body>, Error> {
    let change_password_req: ChangePasswordRequest = match event.payload::<ChangePasswordRequest>()
    {
        Ok(Some(req)) => match ChangePasswordRequest::new(req) {
            Ok(change_password_req) => change_password_req,
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

    if change_password_req.password != change_password_req.confirm_password {
        return Ok(AuthError::PasswordMismatch.to_response());
    }
    if !crate::models::is_strong_password(&change_password_req.password) {
        return Ok(AuthError::CredentialsValidationFailed.to_response());
    }

    // Get user by email
    let user: dbUser = match db_service
        .get_user_by_email(&change_password_req.email)
        .await
    {
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Failed to get user by email: {:?}", e);
            return Ok(e.to_response());
        }
    };

    // Verify old password
    let stored_hash = user.password_hash.clone();
    let old_password = change_password_req.old_password.clone();

    let parsed_hash = argon2::password_hash::PasswordHash::new(&stored_hash)
        .map_err(|e| AuthError::HashingError(e.to_string()))?;

    match Argon2::default().verify_password(old_password.as_bytes(), &parsed_hash) {
        Ok(_) => (),
        Err(e) => {
            tracing::error!("Password verification failed: {:?}", e);
            return Ok(AuthError::InvalidCredentials.to_response()); // Consider more specific error
        }
    }

    // Hash new password
    let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
    let password_hash =
        match Argon2::default().hash_password(change_password_req.password.as_bytes(), &salt) {
            Ok(hash) => hash.to_string(),
            Err(e) => {
                tracing::error!("Hashing error: {:?}", e);
                return Ok(AuthError::HashingError(e.to_string()).to_response());
            }
        };

    // Update password hash in db
    match db_service
        .update_password_hash(&user.user_id, &password_hash)
        .await
    {
        Ok(_) => (),
        Err(e) => {
            tracing::error!("Failed to update password hash: {:?}", e);
            return Ok(e.to_response());
        }
    }

    Ok(Response::builder()
        .status(200)
        .body(Body::from("Password changed successfully"))?)
}

async fn handle_logout(
    event: Request,
    db_service: &DynamoDBServiceUser,
) -> Result<Response<Body>, Error> {
    let logout_req: LogoutRequest = match event.payload::<LogoutRequest>() {
        Ok(Some(req)) => match LogoutRequest::new(req) {
            Ok(logout_req) => logout_req,
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

    // Invalidate token -  You might want to implement token invalidation logic (e.g., blacklist, delete from db)
    // For stateless JWT, client-side deletion is usually sufficient
    // If you are using stateful tokens (stored in DB), you would delete or mark them as invalid here

    Ok(Response::builder()
        .status(200)
        .body(Body::from("Logout successful"))?)
}

async fn handle_update_profile(
    event: Request,
    db_service: &DynamoDBServiceUser,
    email_service: &EmailService,
) -> Result<Response<Body>, Error> {
    let update_profile_req: UpdateProfileRequest = match event.payload::<UpdateProfileRequest>() {
        Ok(Some(req)) => match UpdateProfileRequest::new(req) {
            Ok(update_profile_req) => update_profile_req,
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

    // Get user by email to ensure user exists and for data consistency - alternatively you can use user_uuid if you decide to pass it in request
    let user: dbUser = match db_service
        .get_user_by_email(&update_profile_req.email)
        .await
    {
        // Assuming email is used to identify user for profile update
        Ok(user) => user,
        Err(e) => {
            tracing::error!("Failed to get user by email: {:?}", e);
            return Ok(e.to_response());
        }
    };

    // Validate and update fields -  you might want to validate name, phone, email formats again here as well
    let mut updated_user = user.clone(); // Start with current user data
    updated_user.full_name = update_profile_req.name.clone();
    updated_user.phone = update_profile_req.phone.clone();
    updated_user.email = update_profile_req.email.clone(); // Consider if email update should trigger re-verification

    // Hash new password if provided and valid
    if !update_profile_req.password.is_empty() {
        if update_profile_req.password != update_profile_req.confirm_password {
            return Ok(AuthError::PasswordMismatch.to_response());
        }
        if !crate::models::is_strong_password(&update_profile_req.password) {
            return Ok(AuthError::CredentialsValidationFailed.to_response());
        }

        if !update_profile_req.password.is_empty() {
            let salt = argon2::password_hash::SaltString::generate(&mut OsRng);
            let password_hash = match Argon2::default()
                .hash_password(update_profile_req.password.as_bytes(), &salt)
            {
                Ok(hash) => hash.to_string(),
                Err(e) => {
                    tracing::error!("Hashing error: {:?}", e);
                    return Ok(AuthError::HashingError(e.to_string()).to_response());
                }
            };
            updated_user.password_hash = password_hash; // Update password hash
        }
    }

    // Update user in database
    match db_service.update_user_profile(&updated_user).await {
        // Assuming you will create update_user_profile in DynamoDBServiceUser
        Ok(_) => (),
        Err(e) => {
            tracing::error!("Failed to update user profile: {:?}", e);
            return Ok(e.to_response());
        }
    }

    Ok(Response::builder()
        .status(200)
        .body(Body::from("Profile updated successfully"))?)
}

async fn handle_login(
    event: Request,
    db_service: &DynamoDBServiceUser,
    db_service_auth_token: &DynamoDBServiceUserAuthTokens,
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

    let parsed_hash = match argon2::password_hash::PasswordHash::new(&stored_hash) {
        Ok(hash) => hash,
        Err(e) => {
            tracing::error!("Hashing error: {:?}", e);
            return Ok(AuthError::HashingError(e.to_string()).to_response());
        }
    };

    match Argon2::default().verify_password(password.as_bytes(), &parsed_hash) {
        Ok(_) => (),
        Err(e) => {
            tracing::error!("Password verification failed: {:?}", e);
            return Ok(AuthError::InvalidCredentials.to_response());
        }
    }



    // Update login info
    //db_service.update_login_info(&user.user_id, &ip).await?;

    // Generate JWT token
    let token: String = jwt::generate_token(&user.user_id).unwrap();

    // Create user token
    match db_service_auth_token
        .create_auth_token(&user.user_id, &token, &ip)
        .await
    {
        Ok(_) => (),
        Err(e) => {
            tracing::error!("Failed to create auth token: {:?}", e);
            return Ok(e.to_response());
        }
    };

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
