//crate imports
use aws_sdk_dynamodb::Client;
use aws_sdk_dynamodb::types::AttributeValue;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

//user imports
use crate::error::AuthError;
use crate::models::dbUser;
use crate::models::dbUserToken;

//user service
pub struct DynamoDBServiceUser {
    client: Client,
    table_name: String,
}

impl DynamoDBServiceUser {
    pub fn new(client: Client, table_name: String) -> Self {
        Self {
            client,
            table_name,
        }
    }
    pub async fn create_user(&self, full_name: &str, email: &str, phone: &str, password_hash: &str, ip: &str) -> Result<dbUser, AuthError> {
        let user_uuid = Uuid::new_v4().to_string();
        let user_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let verification_token = Uuid::new_v4().to_string();

        let user = dbUser{
            user_uuid: user_uuid.clone(),
            user_id: user_id.clone(),
            full_name: full_name.to_string(),
            email: email.to_string(),
            phone: phone.to_string(),
            password_hash: password_hash.to_string(),
            created_at: now,
            created_ip: ip.to_string(),
            verified: false,
            verification_token: Some(verification_token.clone()),
            verified_at: None,
            verified_ip: None,
            last_login: None,
            last_login_ip: None,
        };

        let result = self.client
            .put_item()
            .table_name(&self.table_name)
            .item("user_uuid", AttributeValue::S(user_uuid.clone()))
            .item("user_id", AttributeValue::S(user_id.clone()))
            .item("email", AttributeValue::S(email.to_string()))
            .item("phone", AttributeValue::S(phone.to_string()))
            .item("password_hash", AttributeValue::S(password_hash.to_string()))
            .item("full_name", AttributeValue::S(full_name.to_string()))
            .item("created_at", AttributeValue::S(now.to_rfc3339()))
            .item("created_ip", AttributeValue::S(ip.to_string()))
            .item("verified", AttributeValue::Bool(false))
            .item("verification_token", AttributeValue::S(verification_token.clone()))
            .send()
            .await;

        match result {
            Ok(_) => Ok(user),
            Err(e) => Err(AuthError::Internal(e.as_service_error().unwrap().to_string())),
        }

    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<dbUser, AuthError> {
        let result = self.client
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
                    password_hash: item.get("password_hash").unwrap().as_s().unwrap().to_string(),
                    created_at: DateTime::parse_from_rfc3339(item.get("created_at").unwrap().as_s().unwrap())
                        .unwrap()
                        .with_timezone(&Utc),
                    created_ip: item.get("created_ip").unwrap().as_s().unwrap().to_string(),
                    verified: *item.get("verified").unwrap().as_bool().unwrap(),
                    verification_token: item.get("verification_token").map(|v| v.as_s().unwrap().to_string()),
                    verified_at: item.get("verified_at")
                        .map(|v| DateTime::parse_from_rfc3339(v.as_s().unwrap()).unwrap().with_timezone(&Utc)),
                    verified_ip: item.get("verified_ip").map(|v| v.as_s().unwrap().to_string()),
                    last_login: item.get("last_login")
                        .map(|v| DateTime::parse_from_rfc3339(v.as_s().unwrap()).unwrap().with_timezone(&Utc)),
                    last_login_ip: item.get("last_login_ip").map(|v| v.as_s().unwrap().to_string()),
                })
            }
            _ => Err(AuthError::InvalidCredentials),
        }
    }

    pub async fn check_user(&self, email: &str) -> Result<(), AuthError> {
        let result = self.client
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
                    Err(AuthError::EmailAlreadyExists)
                }
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

}

//this is to store Tokens for the user to validate the email , mobile and forgot password 
pub struct DynamoDBServiceUserTokens {
    client: Client,
    table_name: String,
}

impl DynamoDBServiceUserTokens {
    pub fn new(client: Client, table_name: String) -> Self {
        Self {
            client,
            table_name,
        }
    }

    pub async fn create_user_token(&self, user_id: &str, token: &str, ip: &str, token_type: &str) -> Result<(), AuthError> {
        let now = Utc::now();
        let token = Uuid::new_v4().to_string();

        let result = self.client
            .put_item()
            .table_name(&self.table_name)
            .item("user_id", AttributeValue::S(user_id.to_string()))
            .item("token", AttributeValue::S(token.to_string()))
            .item("created_at", AttributeValue::S(now.to_rfc3339()))
            .item("expires_at", AttributeValue::S((now + Duration::days(1)).to_rfc3339()))
            .item("used", AttributeValue::Bool(false))
            .item("used_at", AttributeValue::S(now.to_rfc3339()))
            .item("used_ip", AttributeValue::S(ip.to_string()))
            .item("created_ip", AttributeValue::S(ip.to_string()))
            .item("token_type", AttributeValue::S(token_type.to_string()))
            .send()
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(e) => Err(AuthError::Internal(e.to_string())),
        }
    }   

    pub async fn get_user_token(&self, token: &str) -> Result<dbUserToken, AuthError> {
        let result = self.client
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
                    token_type: item.get("token_type").unwrap().as_s().unwrap().to_string(),
                    created_at: DateTime::parse_from_rfc3339(item.get("created_at").unwrap().as_s().unwrap())
                        .unwrap()
                        .with_timezone(&Utc),
                    expires_at: DateTime::parse_from_rfc3339(item.get("expires_at").unwrap().as_s().unwrap())
                        .unwrap()
                        .with_timezone(&Utc),
                    used: *item.get("used").unwrap().as_bool().unwrap(),
                    used_at: item.get("used_at").map(|v| DateTime::parse_from_rfc3339(v.as_s().unwrap()).unwrap().with_timezone(&Utc)),
                    used_ip: item.get("used_ip").map(|v| v.as_s().unwrap().to_string()),
                    created_ip: item.get("created_ip").unwrap().as_s().unwrap().to_string(),
                })
            }
            None => Err(AuthError::TokenNotFound),
        }
    }

    pub async fn delete_user_token(&self, user_id: &str, token: &str) -> Result<(), AuthError> {
        let result = self.client
            .delete_item()
            .table_name(&self.table_name)
            .key("user_id", AttributeValue::S(user_id.to_string()))
            .key("token", AttributeValue::S(token.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(())
    }
}