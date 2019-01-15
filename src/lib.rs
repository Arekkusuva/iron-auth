extern crate iron;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate jsonwebtoken as jwt;
extern crate r2d2_redis;
extern crate serde_json;

use std::convert::From;
use std::error::Error as stdErr;

use iron::prelude::*;
use iron::{BeforeMiddleware, Handler, typemap, status};
use iron::headers::{Authorization, Bearer};
use r2d2_redis::redis::{IntoConnectionInfo, ToRedisArgs, FromRedisValue, Commands, RedisError, ConnectionInfo};
use r2d2_redis::r2d2::{Pool, Error as ConnError};
use r2d2_redis::{RedisConnectionManager};
use serde_json::Value as JsonValue;

type RedisPool = Pool<RedisConnectionManager>;

// TODO: impl for Error
#[derive(Debug)]
pub enum Error {
    ConnErr(ConnError),
    RedisErr(RedisError),
}

type Result<T> = std::result::Result<T, Error>;

impl From<Error> for Response {
    fn from(_: Error) -> Self {
        let mut res = Response::new();
        res.set_mut(status::InternalServerError);
        res
    }
}

impl From<ConnError> for Error {
    fn from(err: ConnError) -> Self {
        Error::ConnErr(err)
    }
}

impl From<RedisError> for Error {
    fn from(err: RedisError) -> Self {
        Error::RedisErr(err)
    }
}

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
        req.extensions.insert::<AuthConfigKey>(self.clone());
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub exp: usize,

    pub uid: String,
    pub data: Option<JsonValue>,
}

#[derive(Debug)]
pub struct Session {
    pool: RedisPool,
    session_id: String,
    claims: Claims,
}

impl Session {
    pub fn set<V: ToRedisArgs>(&self, key: &str, value: V) -> Result<()> {
        let conn = self.pool.get()?;
        match conn.hset::<&str, &str, V, ()>(&self.session_id, key, value) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn get<RV: FromRedisValue>(&self, key: &str) -> Result<RV> {
        let conn = self.pool.get()?;
        let res = conn.hget(&self.session_id, key)?;
        Ok(res)
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

    #[inline]
    fn get_session_id(uid: &str, token: &str) -> String {
        let session_second_key: String = token.split(".").skip(1).collect();
        format!("{}_{}", uid, session_second_key)
    }

    #[inline]
    fn unauthorized() -> IronResult<Response> {
        Ok(Response::with(status::Unauthorized))
    }
}

pub trait AuthReqExt {
    fn create_token(&mut self, claims: Claims) -> Option<String>;
    fn session(&self) -> Option<&Session>;
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

    fn session(&self) -> Option<&Session> {
        self.extensions.get::<SessionKey>()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
