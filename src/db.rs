//crate imports
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;
use chrono::{DateTime, Duration, Utc};
use std::str::FromStr;
use uuid::Uuid;

//user imports
use crate::error::AuthError;
use crate::models::dbUser;
use crate::models::dbUserToken;
use crate::models::TokenType;
//user service
pub struct DynamoDBServiceUser {
    client: Client,
    table_name: String,
}

impl DynamoDBServiceUser {
    pub fn new(client: Client, table_name: String) -> Self {
        Self { client, table_name }
    }
    pub async fn create_user(
        &self,
        full_name: &str,
        email: &str,
        phone: &str,
        password_hash: &str,
        ip: &str,
    ) -> Result<String, AuthError> {
        let user_uuid = Uuid::new_v4().to_string();
        let user_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .item("user_uuid", AttributeValue::S(user_uuid.clone()))
            .item("user_id", AttributeValue::S(user_id.clone()))
            .item("user_name", AttributeValue::S("".to_string()))
            .item("email", AttributeValue::S(email.to_string()))
            .item("phone", AttributeValue::S(phone.to_string()))
            .item(
                "password_hash",
                AttributeValue::S(password_hash.to_string()),
            )
            .item("full_name", AttributeValue::S(full_name.to_string()))
            .item("created_at", AttributeValue::S(now.to_rfc3339()))
            .item("created_ip", AttributeValue::S(ip.to_string()))
            .item("verified", AttributeValue::Bool(false))
            .item("verified_at", AttributeValue::Null(true))
            .item("verified_ip", AttributeValue::Null(true))
            .item("last_login", AttributeValue::Null(true))
            .item("last_login_ip", AttributeValue::Null(true))
            .send()
            .await;

        match result {
            Ok(_) => Ok(user_id),
            Err(e) => Err(AuthError::Internal(
                e.as_service_error().unwrap().to_string(),
            )),
        }
    }

    pub async fn get_user_by_id(&self, user_id: &str) -> Result<String, AuthError> {
        let result = self
            .client
            .query()
            .table_name(&self.table_name)
            .index_name("user_id-index")
            .key_condition_expression("user_id = :user_id")
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        match result.items {
            Some(items) if !items.is_empty() => {
                let item = &items[0];
                Ok(item.get("user_uuid").unwrap().as_s().unwrap().to_string())
            }
            _ => Err(AuthError::InvalidCredentials),
        }
    }


    pub async fn get_user_by_email(&self, email: &str) -> Result<dbUser, AuthError> {
        let result = self
            .client
            .query()
            .table_name(&self.table_name)
            .index_name("email-index")
            .key_condition_expression("email = :email")
            .expression_attribute_values(":email", AttributeValue::S(email.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        match result.items {
            Some(items) if !items.is_empty() => {
                let item = &items[0];
                Ok(dbUser {
                    user_uuid: item.get("user_uuid").unwrap().as_s().unwrap().to_string(),
                    user_id: item.get("user_id").unwrap().as_s().unwrap().to_string(),
                    full_name: item.get("full_name").unwrap().as_s().unwrap().to_string(),
                    phone: item.get("phone").unwrap().as_s().unwrap().to_string(),
                    email: item.get("email").unwrap().as_s().unwrap().to_string(),
                    password_hash: item
                        .get("password_hash")
                        .unwrap()
                        .as_s()
                        .unwrap()
                        .to_string(),
                    created_at: DateTime::parse_from_rfc3339(
                        item.get("created_at").unwrap().as_s().unwrap(),
                    )
                    .unwrap()
                    .with_timezone(&Utc),
                    verified: *item.get("verified").unwrap().as_bool().unwrap(),
                    user_name: item.get("user_name").unwrap().as_s().unwrap().to_string(),
                })
            }
            _ => Err(AuthError::InvalidCredentials),
        }
    }

    pub async fn check_user(&self, email: &str) -> Result<(), AuthError> {
        let result = self
            .client
            .query()
            .table_name(&self.table_name)
            .index_name("email-index")
            .key_condition_expression("email = :email")
            .expression_attribute_values(":email", AttributeValue::S(email.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        match result.items {
            Some(items) if !items.is_empty() => Err(AuthError::EmailAlreadyExists),
            _ => Ok(()),
        }
    }

    pub async fn update_login_info(&self, user_id: &str, ip: &str) -> Result<(), AuthError> {
        let now = Utc::now();

        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .update_expression("SET last_login = :login_time, last_login_ip = :ip")
            .expression_attribute_values(":login_time", AttributeValue::S(now.to_rfc3339()))
            .expression_attribute_values(":ip", AttributeValue::S(ip.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(())
    }

    pub async fn update_user_verified_status(
        &self,
        user_uuid: &str,
        ip: &str,
 
    ) -> Result<(), AuthError> {
        let now = Utc::now();

        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("user_uuid", AttributeValue::S(user_uuid.to_string()))
            .update_expression("SET verified = :verified, verified_at = :now, verified_ip = :ip")
            .expression_attribute_values(":verified", AttributeValue::Bool(true))
            .expression_attribute_values(":now", AttributeValue::S(now.to_rfc3339()))
            .expression_attribute_values(":ip", AttributeValue::S(ip.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn update_password_hash(
        &self,
        user_id: &str,
        password_hash: &str,
    ) -> Result<(), AuthError> {
        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .update_expression("SET password_hash = :password_hash")
            .expression_attribute_values(
                ":password_hash",
                AttributeValue::S(password_hash.to_string()),
            )
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }

    pub async fn update_user_profile(&self, updated_user: &dbUser) -> Result<(), AuthError> {
        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("user_id", AttributeValue::S(updated_user.user_id.clone()))
            .update_expression("SET full_name = :full_name, phone = :phone, email = :email, password_hash = :password_hash")
            .expression_attribute_values(":full_name", AttributeValue::S(updated_user.full_name.clone()))
            .expression_attribute_values(":phone", AttributeValue::S(updated_user.phone.clone()))
            .expression_attribute_values(":email", AttributeValue::S(updated_user.email.clone()))
            .expression_attribute_values(":password_hash", AttributeValue::S(updated_user.password_hash.clone()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}

//this is to store Tokens for the user to validate the email , mobile and forgot password and other tokens
pub struct DynamoDBServiceUserTokens {
    client: Client,
    table_name: String,
}

impl DynamoDBServiceUserTokens {
    pub fn new(client: Client, table_name: String) -> Self {
        Self { client, table_name }
    }

    // Use this to create tokens for email verification, forgot password etc
    pub async fn create_user_token(
        &self,
        user_id: &str,
        token_type: &TokenType,
        ip: &str,

    ) -> Result<String, AuthError> {
        let now = Utc::now();
        let token = Uuid::new_v4().to_string();

        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .item("user_id", AttributeValue::S(user_id.to_string()))
            .item("token", AttributeValue::S(token.to_string()))
            .item("token_type", AttributeValue::S(token_type.to_string()))
            .item("created_at", AttributeValue::S(now.to_rfc3339()))
            .item(
                "expires_at",
                AttributeValue::S((now + Duration::days(1)).to_rfc3339()),
            )
            .item("used", AttributeValue::Bool(false))
            .item("used_at", AttributeValue::Null(true))
            .item("used_ip", AttributeValue::Null(true))
            .item("created_ip", AttributeValue::S(ip.to_string()))
            .send()
            .await;

        match result {
            Ok(_) => Ok(token),
            Err(e) => Err(AuthError::Internal(e.to_string())),
        }
    }

    pub async fn get_user_token(&self, token: &str) -> Result<dbUserToken, AuthError> {
        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("token", AttributeValue::S(token.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        match result.item {
            Some(item) => {
                Ok(dbUserToken {
                    user_id: item.get("user_id").unwrap().as_s().unwrap().to_string(),
                    token: item.get("token").unwrap().as_s().unwrap().to_string(),
                    token_type: TokenType::from_str(
                        item.get("token_type").unwrap().as_s().unwrap(),
                    )
                    .map_err(|_| AuthError::TokenExpired)?,
                    created_at: DateTime::parse_from_rfc3339(
                        item.get("created_at").unwrap().as_s().unwrap(),
                    )
                    .unwrap()
                    .with_timezone(&Utc),
                    expires_at: DateTime::parse_from_rfc3339(
                        item.get("expires_at").unwrap().as_s().unwrap(),
                    )
                    .unwrap()
                    .with_timezone(&Utc),
                    used: *item.get("used").unwrap().as_bool().unwrap(),
                })
            }
            None => Err(AuthError::TokenNotFound),
        }
    }

    pub async fn delete_user_token(&self, user_id: &str, token: &str) -> Result<(), AuthError> {
        let result = self
            .client
            .delete_item()
            .table_name(&self.table_name)
            .key("token", AttributeValue::S(token.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(())
    }

    pub async fn mark_token_used(&self, token: &str, ip: &str) -> Result<(), AuthError> {
        let now: DateTime<Utc> = Utc::now();
        self.client
            .update_item()
            .table_name(&self.table_name)
            .key("token", AttributeValue::S(token.to_string()))
            .update_expression("SET used = :used, used_at = :used_at, used_ip = :used_ip")
            .expression_attribute_values(":used", AttributeValue::Bool(true))
            .expression_attribute_values(":used_at", AttributeValue::S(now.to_rfc3339()))
            .expression_attribute_values(":used_ip", AttributeValue::S(ip.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}

//this is to store User Auth Tokens for session management (JWT tokens)
pub struct DynamoDBServiceUserAuthTokens {
    client: Client,
    table_name: String,
}

impl DynamoDBServiceUserAuthTokens {
    pub fn new(client: Client, table_name: String) -> Self {
        Self { client, table_name }
    }

    // Use this to create auth tokens for session management (JWT tokens)
    pub async fn create_auth_token(
        &self,
        user_id: &str,
        token: &str,
        ip: &str,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        let result = self
            .client
            .put_item()
            .table_name(&self.table_name)
            .item("user_id", AttributeValue::S(user_id.to_string()))
            .item("token", AttributeValue::S(token.to_string()))
            .item("created_at", AttributeValue::S(now.to_rfc3339()))
            .item(
                "expires_at",
                AttributeValue::S((now + Duration::days(30)).to_rfc3339()),
            ) // Session tokens expire in 30 days
            .item("created_ip", AttributeValue::S(ip.to_string()))
            .item("session_start_time", AttributeValue::S(now.to_rfc3339()))
            .item("session_ip", AttributeValue::S(ip.to_string()))
            .send()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(AuthError::Internal(e.to_string())),
        }
    }

    pub async fn get_auth_token(&self, token: &str) -> Result<dbUserToken, AuthError> {
        let result = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("token", AttributeValue::S(token.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        match result.item {
            Some(item) => {
                Ok(dbUserToken {
                    user_id: item.get("user_id").unwrap().as_s().unwrap().to_string(),
                    token: item.get("token").unwrap().as_s().unwrap().to_string(),
                    // token type is not relevant for auth tokens
                    token_type: TokenType::from_str(
                        item.get("token_type").unwrap().as_s().unwrap(),
                    )
                    .map_err(|_| AuthError::TokenExpired)?,
                    created_at: DateTime::parse_from_rfc3339(
                        item.get("created_at").unwrap().as_s().unwrap(),
                    )
                    .unwrap()
                    .with_timezone(&Utc),
                    expires_at: DateTime::parse_from_rfc3339(
                        item.get("expires_at").unwrap().as_s().unwrap(),
                    )
                    .unwrap()
                    .with_timezone(&Utc),
                    // used and used_at is not relevant for auth tokens
                    used: false,
                })
            }
            None => Err(AuthError::TokenNotFound),
        }
    }

    pub async fn delete_auth_token(&self, token: &str) -> Result<(), AuthError> {
        let result = self
            .client
            .delete_item()
            .table_name(&self.table_name)
            .key("token", AttributeValue::S(token.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;
        Ok(())
    }
}
