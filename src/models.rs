use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tokio::task::Id;
use crate::error::AuthError;


/* Database Models */

#[derive(Debug, Serialize, Deserialize)]
pub struct dbUser {
    pub user_uuid: String,
    pub user_id: String,
    pub full_name: String,
    pub email: String,
    pub phone: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub created_ip: String,
    pub verified: bool,
    pub verification_token: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub verified_ip: Option<String>,
    pub last_login: Option<DateTime<Utc>>,
    pub last_login_ip: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct dbUserToken {
    pub user_id: String,
    pub token: String,
    pub token_type: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub used_at: Option<DateTime<Utc>>,
    pub used_ip: Option<String>,
    pub created_ip: String,
}



/* Request Models */

#[derive(Debug, Serialize, Deserialize)]
pub struct IDUniRequest {
    pub email: String,
    pub password: String,
    pub name: String,
    pub phone: String,
    pub confirm_password	: String,
    pub token: String,
    pub token_type: String,
    pub ip: String,    
    pub password_hash: String,
    pub username: String,
}

impl IDUniRequest {
    pub fn new(id_req: IDUniRequest) -> Result<Self, AuthError> {
       
        Ok(id_req)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
    pub ip: String,
}

impl ForgotPasswordRequest {
    pub fn new(forgot_password_req: ForgotPasswordRequest) -> Result<Self, AuthError> {
        Ok(forgot_password_req)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub email: String,
    pub password: String,
    pub confirm_password: String,
    pub old_password: String,
}

impl ChangePasswordRequest {
    pub fn new(change_password_req: ChangePasswordRequest) -> Result<Self, AuthError> {
        Ok(change_password_req)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogoutRequest {
    pub user_uuid: String,
    pub token: String,
    pub ip: String,
}

impl LogoutRequest {
    pub fn new(logout_req: LogoutRequest) -> Result<Self, AuthError> {
        Ok(logout_req)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateProfileRequest {
    pub user_uuid: String,
    pub token: String,
    pub ip: String,
    pub name: String,
    pub phone: String,
    pub email: String,
    pub password: String,
    pub confirm_password: String,
}

impl UpdateProfileRequest {
    pub fn new(update_profile_req: UpdateProfileRequest) -> Result<Self, AuthError> {
        Ok(update_profile_req)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub token: String,

}

impl VerifyRequest {
    pub fn new(verify_req: VerifyRequest) -> Result<Self, AuthError> {
        Ok(verify_req)
    }
}




#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

impl LoginRequest {
    pub fn new(login_req: LoginRequest) -> Result<Self, AuthError> {
        if !is_valid_email(&login_req.username) {
            return Err(AuthError::InvalidEmail);
        }
        Ok(login_req)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub name: String,
    #[serde(default)]
    pub phone: String,
    pub confirm_password	: String,
}

impl RegisterRequest {
    pub fn new(register_req: RegisterRequest) -> Result<Self, AuthError> {
        if !is_valid_email(&register_req.email) {
            return Err(AuthError::InvalidEmail);
        }
        if !is_valid_indian_mobile(&register_req.phone) {
            return Err(AuthError::InvalidPhone);
        }
        if register_req.name.is_empty() {
            return Err(AuthError::InvalidFullName);
        }
        if !is_strong_password(&register_req.password) {
            return Err(AuthError::CredentialsValidationFailed);
        }
        Ok(register_req)
    }
}









pub fn is_valid_email(email: &str) -> bool {
    // Check for exactly one '@' and split into parts
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    let (local, domain) = (parts[0], parts[1]);

    // Validate local part
    if local.is_empty() || local.len() > 64 {
        return false;
    }

    // Check local part characters and format
    let mut prev_char = '.';
    for c in local.chars() {
        if !c.is_alphanumeric() && !"._-+%".contains(c) {
            return false;
        }
        if prev_char == '.' && c == '.' {
            return false;
        }
        prev_char = c;
    }

    if local.starts_with('.') || local.ends_with('.') {
        return false;
    }

    // Validate domain part
    if domain.is_empty() || domain.len() > 255 {
        return false;
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        for c in label.chars() {
            if !c.is_alphanumeric() && c != '-' {
                return false;
            }
        }
    }

    // Check TLD length
    if let Some(tld) = labels.last() {
        tld.len() >= 2
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(is_valid_email("user.name@example.com"));
        assert!(is_valid_email("user_name@example.co.uk"));
        assert!(is_valid_email("user+label@example.org"));
        assert!(is_valid_email("user-name@example.io"));
        assert!(is_valid_email("u@example.me"));
    }

    #[test]
    fn test_invalid_emails() {
        assert!(!is_valid_email("plainaddress"));       // Missing @
        assert!(!is_valid_email("user@.com"));          // Empty domain label
        assert!(!is_valid_email("user@domain..com"));   // Consecutive dots in domain
        assert!(!is_valid_email(".user@example.com"));  // Leading dot in local
        assert!(!is_valid_email("user.@example.com"));  // Trailing dot in local
        assert!(!is_valid_email("user@-example.com"));  // Leading hyphen in domain label
        assert!(!is_valid_email("user@example.c"));     // TLD too short
        assert!(!is_valid_email("user@example"));       // Missing TLD
        assert!(!is_valid_email("user@example_com"));   // Underscore in domain
        assert!(!is_valid_email("user@example..com"));  // Consecutive dots in domain
        assert!(!is_valid_email("user@example.com."));  // Trailing dot in domain
    }
}


pub fn is_valid_indian_mobile(number: &str) -> bool {
    // Sanitize input by removing all non-digit characters
    let sanitized: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    let len = sanitized.len();

    match len {
        10 => {
            // Check for 10-digit numbers starting with 6-9
            sanitized.starts_with(|c| matches!(c, '6'..='9'))
        }
        11 => {
            // Check for numbers with leading 0 followed by 10 digits
            sanitized.starts_with('0') && 
            sanitized[1..].starts_with(|c| matches!(c, '6'..='9'))
        }
        12 => {
            // Check for numbers with country code 91 followed by 10 digits
            sanitized.starts_with("91") && 
            sanitized[2..].starts_with(|c| matches!(c, '6'..='9'))
        }
        _ => false,
    }
}

#[cfg(test)]
mod mobile_tests {
    use super::*;

    #[test]
    fn test_valid_mobiles() {
        assert!(is_valid_indian_mobile("9876543210"));      // Standard 10-digit
        assert!(is_valid_indian_mobile("09123456789"));     // With leading 0
        assert!(is_valid_indian_mobile("919876543210"));    // With country code 91
        assert!(is_valid_indian_mobile("+91 9876 543 210"));// With country code and spaces
        assert!(is_valid_indian_mobile("61234-56789"));     // With hyphen
        assert!(is_valid_indian_mobile("73 4567 8901"));    // With spaces
    }

    #[test]
    fn test_invalid_mobiles() {
        assert!(!is_valid_indian_mobile("987654321"));       // Too short
        assert!(!is_valid_indian_mobile("0912345678"));      // Invalid length after 0
        assert!(!is_valid_indian_mobile("5123456789"));      // Starts with 5
        assert!(!is_valid_indian_mobile("919512345678"));    // Invalid digit after 91
        assert!(!is_valid_indian_mobile("0@5123A56789"));    // Invalid characters
        assert!(!is_valid_indian_mobile("12345678901"));     // Invalid starting digit
        assert!(!is_valid_indian_mobile("919abcdef456"));    // Non-digit characters
        assert!(!is_valid_indian_mobile(""));                // Empty input
    }
}

pub fn is_strong_password(password: &str) -> bool {
    if password.len() < 8 {
        return false;
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;

    for c in password.chars() {
        match c {
            'a'..='z' => has_lower = true,
            'A'..='Z' => has_upper = true,
            '0'..='9' => has_digit = true,
            _ if c.is_ascii_punctuation() => has_special = true,
            _ => {} // Ignore other characters
        }
    }

    has_lower && has_upper && has_digit && has_special
}

#[cfg(test)]
mod password_tests {
    use super::*;

    #[test]
    fn test_valid_passwords() {
        assert!(is_strong_password("Passw0rd!"));    // All requirements
        assert!(is_strong_password("Aa1!aaaa"));     // Minimum length
        assert!(is_strong_password("Secur3P@ss"));   // Mixed case with special
        assert!(is_strong_password("Winter2023#"));  // Special character at end
        assert!(is_strong_password("P@ssw0rd"));     // Classic format
    }

    #[test]
    fn test_invalid_passwords() {
        assert!(!is_strong_password(""));            // Empty
        assert!(!is_strong_password("short"));       // Too short
        assert!(!is_strong_password("alllowercase1!")); // No uppercase
        assert!(!is_strong_password("ALLUPPERCASE1!")); // No lowercase
        assert!(!is_strong_password("PasswordWithoutDigit!")); // No number
        assert!(!is_strong_password("Passw0rd"));    // Missing special
        assert!(!is_strong_password("12345678!"));   // Missing letters
        assert!(!is_strong_password("PaSsWoRd"));    // Missing number and special
    }
}
