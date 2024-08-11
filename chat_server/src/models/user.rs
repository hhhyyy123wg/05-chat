use std::mem;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::{AppError, User};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUser {
    pub fullname: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigninUser {
    pub email: String,
    pub password: String,
}

impl User {
    /// Find user by email
    pub async fn find_by_email(email: &str, pool: &sqlx::PgPool) -> Result<Option<Self>, AppError> {
        let user = sqlx::query_as(
            r#"
                SELECT id,fullname,email,created_at
                FROM users
                WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(pool)
        .await?;
        Ok(user)
    }

    /// Create a new user
    pub async fn create(input: &CreateUser, pool: &PgPool) -> Result<Self, AppError> {
        let password_hash = hash_password(&input.password)?;
        // check if email exists
        let user = Self::find_by_email(&input.email, pool).await?;
        if user.is_some() {
            return Err(AppError::EmailAlreadyExists(input.email.clone()));
        }
        let user = sqlx::query_as(
            r#"
                INSERT INTO users (email, fullname, password_hash)
                VALUES ($1, $2, $3)
                RETURNING id, fullname, email, created_at
                "#,
        )
        .bind(&input.email)
        .bind(&input.fullname)
        .bind(password_hash)
        .fetch_one(pool)
        .await?;
        Ok(user)
    }

    /// Verify email and password
    pub async fn verify(input: &SigninUser, pool: &sqlx::PgPool) -> Result<Option<Self>, AppError> {
        let usr: Option<User> = sqlx::query_as(
            r#"
                SELECT id,fullname,email,password_hash,created_at
                FROM users
                WHERE email = $1
            "#,
        )
        .bind(&input.email)
        .fetch_optional(pool)
        .await?;

        match usr {
            Some(mut usr) => {
                let password_hash = mem::take(&mut usr.password_hash);
                let verified =
                    verify_password(&input.password, password_hash.unwrap_or_default().as_ref())?;
                if verified {
                    Ok(Some(usr))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}

fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();

    Ok(password_hash)
}

fn verify_password(password: &str, password_hash: &str) -> Result<bool, AppError> {
    let parsed_hash = PasswordHash::new(password_hash)?;

    // Verify password against PHC string
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash);

    Ok(result.is_ok())
}

#[cfg(test)]
impl User {
    pub fn new(id: i64, fullname: &str, email: &str) -> Self {
        Self {
            id,
            fullname: fullname.to_string(),
            email: email.to_string(),
            password_hash: None,
            created_at: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
impl CreateUser {
    pub fn new(fullname: &str, email: &str, password: &str) -> Self {
        Self {
            fullname: fullname.to_string(),
            email: email.to_string(),
            password: password.to_string(),
        }
    }
}

#[cfg(test)]
impl SigninUser {
    pub fn new(email: &str, password: &str) -> Self {
        Self {
            email: email.to_string(),
            password: password.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use anyhow::Result;
    use sqlx_db_tester::TestPg;

    #[test]
    fn hash_password_and_verify_should_work() -> Result<()> {
        let password = "password";
        let password_hash = hash_password(password)?;
        assert_eq!(password_hash.len(), 97);
        let verified = verify_password(password, &password_hash)?;
        assert!(verified);
        Ok(())
    }

    #[tokio::test]
    async fn verify_user_should_fail() -> Result<()> {
        let tdb = TestPg::new(
            "postgres://postgres:postgres@localhost:5432".to_string(),
            Path::new("../migrations"),
        );
        let pool = tdb.get_pool().await;
        let input = CreateUser::new("test", "test@test.com", "password");
        User::create(&input, &pool).await?;
        let ret = User::create(&input, &pool).await;

        match ret {
            Err(AppError::EmailAlreadyExists(email)) => {
                assert_eq!(email, input.email);
            }
            _ => {
                panic!("should fail");
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn create_and_verify_user_should_work() -> Result<()> {
        let tdb = TestPg::new(
            "postgres://postgres:postgres@localhost:5432".to_string(),
            Path::new("../migrations"),
        );
        let pool = tdb.get_pool().await;
        let input = CreateUser::new("test", "test@test.com", "password");

        let user = User::create(&input, &pool).await?;
        assert_eq!(user.email, input.email);
        assert_eq!(user.fullname, input.fullname);
        assert!(user.id > 0);

        let user = User::find_by_email(&input.email, &pool).await?;
        assert!(user.is_some());
        let user = user.unwrap();
        assert_eq!(user.email, input.email);
        assert_eq!(user.fullname, input.fullname);

        let input = SigninUser::new(&input.email, &input.password);
        let user = User::verify(&input, &pool).await?;
        assert!(user.is_some());

        Ok(())
    }
}
