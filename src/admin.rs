use rocket::{
    http::Status,
    request::{self, FromRequest},
    Request,
};

pub struct Admin {
    pub username: String,
}

#[derive(Debug)]
pub enum AdminError {
    Missing,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Admin {
    type Error = AdminError;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let username = match req.headers().get("X-Forwarded-Preferred-Username").next() {
            Some(username) => username,
            None => return request::Outcome::Error((Status::BadRequest, AdminError::Missing)),
        };

        request::Outcome::Success(Admin {
            username: username.to_string(),
        })
    }
}
