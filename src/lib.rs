extern crate iron;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate jsonwebtoken as jwt;
extern crate r2d2_redis;
extern crate serde_json;

use iron::prelude::*;
use iron::{typemap, status, BeforeMiddleware, Handler};
use iron::headers::{Authorization, Bearer};
use r2d2_redis::redis::{IntoConnectionInfo, ConnectionInfo};
use r2d2_redis::r2d2::Pool;
use r2d2_redis::RedisConnectionManager;
use serde_json::Value as JsonValue;

type RedisPool = Pool<RedisConnectionManager>;

#[derive(Debug, Clone)]
pub struct AuthConfigMiddleware {
    pub secret: String,
    pub redis_params: ConnectionInfo,
}

impl AuthConfigMiddleware {
    pub fn new<P: IntoConnectionInfo>(secret: String, redis_params: P) -> AuthConfigMiddleware {
        AuthConfigMiddleware {
            secret,
            redis_params: redis_params.into_connection_info().expect("redis params")
        }
    }
}

struct AuthConfigKey;

impl typemap::Key for AuthConfigKey { type Value = AuthConfigMiddleware; }

impl BeforeMiddleware for AuthConfigMiddleware {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        req.extensions.insert::<AuthConfigKey>(self.clone()).unwrap();
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub uid: String,
    pub data: JsonValue,
    pub exp: usize,
}

pub struct Session {
    pool: RedisPool,
    session_id: (String, String),
    claims: Claims,
}

impl Session {
    pub fn set<V: Into<String>>(&self, key: &str, value: V) {
        unimplemented!()
    }

    pub fn get<V: From<String>>(&self, key: &str) -> Option<V> {
        unimplemented!()
    }

    pub fn get_claims(&self) -> Claims {
        self.claims.clone()
    }
}

struct SessionKey;

impl typemap::Key for SessionKey { type Value = Session; }

pub struct AuthWrapper;

impl AuthWrapper {
    pub fn wrap<H: Handler>(handler: H) -> impl Handler {
        move |req: &mut Request| {
            match req.extensions.remove::<AuthConfigKey>() {
                Some(b) => {
                    let manager = RedisConnectionManager::new(b.redis_params.clone()).unwrap();
                    let pool = Pool::builder()
                        .build(manager)
                        .unwrap();

                    let token = match req.headers.get::<Authorization<Bearer>>() {
                        Some(b) => b.token.clone(),
                        None => return Self::unauthorized(),
                    };

                    let claims: Claims = match jwt::decode(&token, b.secret.clone().as_bytes(), &jwt::Validation::default()) {
                        Ok(t) => t.claims,
                        Err(_) => return Self::unauthorized(),
                    };

                    let session_id = Self::get_session_id(&claims.uid, &token);

                    let session = Session {
                        pool,
                        session_id,
                        claims,
                    };
                    req.extensions.insert::<SessionKey>(session);
                    req.extensions.insert::<AuthConfigKey>(b);
                    handler.handle(req)
                },
                None => Self::unauthorized(),
            }
        }
    }

    fn get_session_id(uid: &str, token: &str) -> (String, String) {
        let session_second_key: String = token.split(".").skip(1).collect();
        (format!("{}_t", uid), session_second_key)
    }

    fn unauthorized() -> IronResult<Response> {
        Ok(Response::with(status::Unauthorized))
    }
}

pub trait AuthReqExt {
    fn create_token(&mut self, claims: Claims) -> Option<String>;
    fn session(&self) -> &Session;
}

impl<'a, 'b> AuthReqExt for Request<'a, 'b> {
    fn create_token(&mut self, claims: Claims) -> Option<String> {
        match self.extensions.get::<AuthConfigKey>() {
            Some(b) => {
                let token = jwt::encode(&jwt::Header::default(), &claims, b.secret.as_ref()).unwrap();
                Some(token)
            },
            None => None,
        }
    }

    fn session(&self) -> &Session {
        self.extensions.get::<SessionKey>().unwrap()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
