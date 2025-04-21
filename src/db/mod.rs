pub(crate) mod users {
    use argon2::{
        password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
        Argon2,
    };
    use log::info;
    use sqlx::{sqlite::SqlitePool, Row};
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum DbError {
        #[error("Database error: {0}")]
        Database(#[from] sqlx::Error),
        #[error("Password hashing error: {0}")]
        Hashing(argon2::password_hash::Error),
        #[error("User not found")]
        UserNotFound,
    }

    pub async fn connect_to_db() -> Result<SqlitePool, sqlx::Error> {
        let pool = SqlitePool::connect("sqlite:./db.sqlite").await?;
        Ok(pool)
    }

    pub async fn create_db_pool() -> Result<SqlitePool, sqlx::Error> {
        let pool = connect_to_db().await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(pool)
    }

    pub async fn get_user_by_username(
        username: &str,
    ) -> Result<Option<(i64, String)>, sqlx::Error> {
        let pool = create_db_pool().await?;

        let user = sqlx::query(
            r#"
            SELECT id, username
            FROM users
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&pool)
        .await?;

        Ok(user.map(|row| (row.get(0), row.get(1))))
    }

    pub async fn check_for_account(username: &str) -> Result<bool, sqlx::Error> {
        // Fixed error type
        let pool = create_db_pool().await?;

        let exists = sqlx::query(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM users
                WHERE username = ?
            )
            "#,
        )
        .bind(username)
        .fetch_one(&pool)
        .await?
        .get::<i64, _>(0);

        Ok(exists == 1)
    }

    pub async fn create_user(username: &str, password_hash: &str) -> Result<(), sqlx::Error> {
        let pool = create_db_pool().await?;

        sqlx::query(
            r#"
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
            "#,
        )
        .bind(username)
        .bind(password_hash)
        .execute(&pool)
        .await?;
        Ok(())
    }

    pub async fn hash_password(password: &str) -> String {
        let salt = SaltString::generate(&mut rand::thread_rng());
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("Failed to hash password");
        password_hash.to_string()
    }

    pub async fn verify_password(
        // Use clearer argument names
        username: &str,
        provided_password: &str,
    ) -> Result<bool, DbError> {
        let pool = create_db_pool().await?; // Propagates sqlx::Error

        // Fetch the stored hash for the user
        let user_row = sqlx::query(
            r#"
            SELECT password_hash
            FROM users
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&pool) // Use fetch_optional to handle not found case
        .await?;

        // Get the stored hash string or return error if user not found
        let stored_hash_str = match user_row {
            Some(row) => row.get::<String, _>(0),
            None => return Err(DbError::UserNotFound),
        };

        // Parse the stored hash
        let parsed_hash = PasswordHash::new(&stored_hash_str).map_err(DbError::Hashing)?; // Manually map the error

        let argon2 = Argon2::default();

        let verification_result =
            argon2.verify_password(provided_password.as_bytes(), &parsed_hash);

        // Check the result and return true/false accordingly
        match verification_result {
            Ok(()) => {
                info!("Password check successful for user: {}", username);
                Ok(true)
            }
            Err(argon2::password_hash::Error::Password) => {
                info!("Password check failed (mismatch) for user: {}", username);
                Ok(false)
            }
            Err(e) => {
                // Handle other potential argon2 errors (e.g., invalid hash format)
                info!(
                    "Password check failed for user {} with error: {}",
                    username, e
                );
                Err(DbError::Hashing(e))
            }
        }
    }
}
