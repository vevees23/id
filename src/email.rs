use aws_sdk_ses::Client;
use aws_sdk_ses::types::Destination;
use aws_sdk_ses::types::{Body, Content, Message};
use crate::error::AuthError;

pub struct EmailService {
    client: Client,
    from_email: String,
}

impl EmailService {
    pub fn new(client: Client, from_email: String) -> Self {
        Self {
            client,
            from_email,
        }
    }

    pub async fn send_verification_email(
        &self,
        to_email: &str,
        verification_token: &str,
    ) -> Result<(), AuthError> {
        let verification_link = format!(
            "https://auth.dev.phazor.in/verify?token={}",
            verification_token
        );

        let subject_content = Content::builder()
            .data("Verify your email address")
            .charset("UTF-8")
            .build()
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let body_html = format!(
            r#"
            <h1>Welcome!</h1>
            <p>Please click the link below to verify your email address:</p>
            <p><a href="{}">Verify Email</a></p>
            <p>If you didn't create an account, please ignore this email.</p>
            "#,
            verification_link
        );

        let body_html_content = Content::builder()
            .data(body_html)
            .charset("UTF-8")
            .build()
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let body = Body::builder()
            .html(body_html_content)
            .build();

        let message = Message::builder()
            .subject(subject_content)
            .body(body)
            .build();

        let destination = Destination::builder()
            .to_addresses(to_email.to_string())
            .build();

        self.client
            .send_email()
            .source(self.from_email.clone())
            .destination(destination)
            .message(message)
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(())
    }

    pub async fn send_forgot_password_email(
        &self,
        to_email: &str,
        reset_password_token: &str,
    ) -> Result<(), AuthError> {
        let reset_password_link = format!(
            "https://auth.dev.phazor.in/change-password?token={}",
            reset_password_token
        );

        let subject_content = Content::builder()
            .data("Reset your password")
            .charset("UTF-8")
            .build()
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let body_html = format!(
            r#"
            <h1>Forgot your password?</h1>
            <p>Please click the link below to reset your password:</p>
            <p><a href="{}">Reset Password</a></p>
            <p>If you didn't request a password reset, please ignore this email.</p>
            "#,
            reset_password_link
        );

        let body_html_content = Content::builder()
            .data(body_html)
            .charset("UTF-8")
            .build()
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        let body = Body::builder()
            .html(body_html_content)
            .build();

        let message = Message::builder()
            .subject(subject_content)
            .body(body)
            .build();

        let destination = Destination::builder()
            .to_addresses(to_email.to_string())
            .build();

        self.client
            .send_email()
            .source(self.from_email.clone())
            .destination(destination)
            .message(message)
            .send()
            .await
            .map_err(|e| AuthError::Internal(e.to_string()))?;

        Ok(())
    }
}
