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

    pub async fn check_ban(username: &str) -> Result<bool, sqlx::Error> {
        let pool = create_db_pool().await?;

        let is_banned = sqlx::query(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM users
                WHERE username = ? AND is_banned = 1
            )
            "#,
        )
        .bind(username)
        .fetch_one(&pool)
        .await?
        .get::<i64, _>(0);

        // Check if the user is banned
        if is_banned == 1 {
            info!("User {} is banned", username);
        } else {
            info!("User {} is not banned", username);
        }

        Ok(is_banned == 1)
    }

    pub async fn get_ban_reason(username: &str) -> Result<Option<String>, sqlx::Error> {
        let pool = create_db_pool().await?;
        info!("Attempting to fetch ban reason for user: {}", username);

        let row_option = sqlx::query(
            r#"
            SELECT ban_reason
            FROM users
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&pool)
        .await?;

        // Process the result
        match row_option {
            Some(row) => {
                // Row found, now get the ban_reason (which might be NULL)
                let reason: Option<String> = row.get(0); // Type annotation clarifies intent
                if let Some(ref r) = reason {
                    info!("User {} found. Ban reason: {}", username, r);
                } else {
                    // User exists, but ban_reason is NULL in the database
                    info!(
                        "User {} found, but ban_reason is NULL (not banned)",
                        username
                    );
                }
                Ok(reason)
            }
            None => {
                // No row found for the username
                info!("User {} not found in the database", username);
                // Return Ok(None) as per the function signature, indicating no ban reason found
                // because the user doesn't exist.
                Ok(None)
            }
        }
    }

    pub async fn ban_user(username: &str, ban_reason: &str) -> Result<(), sqlx::Error> {
        let pool = create_db_pool().await?;

        // Use a single query to update the user
        sqlx::query(
            r#"
            UPDATE users
            SET is_banned = 1, ban_reason = ?
            WHERE username = ?
            "#,
        )
        .bind(ban_reason)
        .bind(username)
        .execute(&pool)
        .await?;

        Ok(())
    }

    pub async fn unban_user(username: &str) -> Result<(), sqlx::Error> {
        let pool = create_db_pool().await?;

        // Use a single query to update the user
        sqlx::query(
            r#"
            UPDATE users
            SET is_banned = 0, ban_reason = NULL
            WHERE username = ?
            "#,
        )
        .bind(username)
        .execute(&pool)
        .await?;

        Ok(())
    }

    pub async fn change_password(username: &str, new_password: &str) -> Result<(), sqlx::Error> {
        let pool = create_db_pool().await?;

        // Hash the new password
        let new_password_hash = hash_password(new_password).await;

        // Update the password in the database
        sqlx::query(
            r#"
            UPDATE users
            SET password_hash = ?
            WHERE username = ?
            "#,
        )
        .bind(new_password_hash)
        .bind(username)
        .execute(&pool)
        .await?;

        Ok(())
    }

    pub async fn verify_password(username: &str, provided_password: &str) -> Result<bool, DbError> {
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
        let parsed_hash = PasswordHash::new(&stored_hash_str).map_err(DbError::Hashing)?;
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

    pub async fn verify_admin(username: &str) -> Result<bool, sqlx::Error> {
        let pool = create_db_pool().await?;

        let is_admin = sqlx::query(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM users
                WHERE username = ? AND is_admin = 1
            )
            "#,
        )
        .bind(username)
        .fetch_one(&pool)
        .await?
        .get::<i64, _>(0);

        Ok(is_admin == 1)
    }

    pub async fn add_kick(username: &str) -> Result<(), sqlx::Error> {
        let pool = create_db_pool().await?;

        sqlx::query(
            r#"
            INSERT INTO kick (user_name)
            VALUES (?)
            "#,
        )
        .bind(username)
        .execute(&pool)
        .await?;
        Ok(())
    }

    pub async fn remove_kick(username: &str) -> Result<(), sqlx::Error> {
        let pool = create_db_pool().await?;

        sqlx::query(
            r#"
            DELETE FROM kick
            WHERE user_name = ?
            "#,
        )
        .bind(username)
        .execute(&pool)
        .await?;
        Ok(())
    }

    pub async fn check_kick(username: &str) -> Result<bool, sqlx::Error> {
        let pool = create_db_pool().await?;

        let exists = sqlx::query(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM kick
                WHERE user_name = ?
            )
            "#,
        )
        .bind(username)
        .fetch_one(&pool)
        .await?
        .get::<i64, _>(0);

        Ok(exists == 1)
    }

    pub async fn add_new_file(name: &str, link: &str) -> Result<(), sqlx::Error> {
        let pool = create_db_pool().await?;

        sqlx::query(
            r#"
            INSERT INTO files (name, path)
            VALUES (?, ?)
            "#,
        )
        .bind(name)
        .bind(link)
        .execute(&pool)
        .await?;
        Ok(())
    }

    pub async fn request_file(name: &str) -> Result<String, sqlx::Error> {
        let pool = create_db_pool().await?;

        let file_path = sqlx::query(
            r#"
            SELECT path
            FROM files
            WHERE name = ?
            "#,
        )
        .bind(name)
        .fetch_one(&pool)
        .await?
        .get::<String, _>(0);

        Ok(file_path)
    }

    pub async fn add_verified_flag_to_file(name: &str) -> Result<(), sqlx::Error> {
        let pool = create_db_pool().await?;

        sqlx::query(
            r#"
            UPDATE files
            SET admin_verified = 1
            WHERE name = ?
            "#,
        )
        .bind(name)
        .execute(&pool)
        .await?;
        Ok(())
    }

    pub async fn check_file_verified(name: &str) -> Result<bool, sqlx::Error> {
        let pool = create_db_pool().await?;

        let is_verified = sqlx::query(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM files
                WHERE name = ? AND admin_verified = 1
            )
            "#,
        )
        .bind(name)
        .fetch_one(&pool)
        .await?
        .get::<i64, _>(0);

        Ok(is_verified == 1)
    }
}
