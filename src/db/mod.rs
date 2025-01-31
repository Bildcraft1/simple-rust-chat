pub(crate) mod users {
    use sqlx::sqlite::SqlitePool;

    pub async fn connect_to_db() -> Result<SqlitePool, sqlx::Error> {
        let pool = SqlitePool::connect("sqlite:./db.sqlite").await?;
        Ok(pool)
    }

    pub async fn create_db_pool() -> Result<SqlitePool, sqlx::Error> {
        let pool = connect_to_db().await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(pool)
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
}
