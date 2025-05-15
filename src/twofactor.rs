use rocket_db_pools::Connection;
use sqlx::query;

use crate::{admin::Admin, Cmdb};

#[get("/?<cid>&<ip>")]
pub async fn twofactor_validate(
    mut db: Connection<Cmdb>,
    admin: Admin,
    cid: &str,
    ip: &str,
) -> String {
    match query("UPDATE twofactor SET approved = 1 WHERE cid = ? AND ckey = ? AND ip = ?")
        .bind(&cid)
        .bind(&admin.username)
        .bind(&ip)
        .execute(&mut **db)
        .await
    {
        Ok(res) => {
            if res.rows_affected() > 0 {
                "Two factor request updated.".to_string()
            } else {
                format!("An error occured: could not find match for ckey: {}, cid: {}, ip: {}.", &cid, &admin.username, &ip)
            }
        }
        Err(err) => format!("An error occured: {:?}", err).to_string(),
    }
}
