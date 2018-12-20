extern crate iron;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate jsonwebtoken as jwt;
extern crate r2d2_redis;

mod backends;

use iron::prelude::*;
use iron::{typemap, status, BeforeMiddleware, Handler};
use r2d2_redis::redis::{IntoConnectionInfo, ConnectionInfo};

#[derive(Debug, Clone)]
pub enum AuthMethod {
    JWT,
}

pub trait RawSession {
    fn set_raw(&self, key: &str, value: String);
    fn get_raw(&self, key: &str) -> Option<String>;
}

pub trait AuthSessionBackend: Send + Sync +'static {
    type S: RawSession;

    fn get_session_from_request(&self, req: &mut Request) -> Option<Self::S>;
}

#[derive(Debug, Clone)]
pub struct AuthConfigMiddleware {
    pub method: AuthMethod,
    pub secret: String,
    pub redis_params: ConnectionInfo,
}

impl AuthConfigMiddleware {
    pub fn with<P: IntoConnectionInfo>(method: AuthMethod, secret: String, redis_params: P) -> AuthConfigMiddleware {
        AuthConfigMiddleware {
            method,
            secret,
            redis_params: redis_params.into_connection_info().expect("redis params")
        }
    }

    pub fn with_secret(method: AuthMethod, secret: String) -> AuthConfigMiddleware {
        AuthConfigMiddleware::with(method, secret, "redis://localhost")
    }
}

struct AuthConfigKey;
// TODO: Figure out how to use AuthSessionBackend as key.
impl typemap::Key for AuthConfigKey { type Value = AuthConfigMiddleware; }

impl BeforeMiddleware for AuthConfigMiddleware {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        req.extensions.insert::<AuthConfigKey>(self.clone()).unwrap();
        Ok(())
    }
}

pub struct Session {
    raw: Box<RawSession>,
}

impl Session {
    pub fn new(raw_session: Box<RawSession>) -> Session {
        Session {
            raw: raw_session,
        }
    }

    pub fn set<V: Into<String>>(self, key: &str, value: V) {
        self.raw.set_raw(key, value.into())
    }

    pub fn get<V: From<String>>(self, key: &str) -> Option<V> {
        match self.raw.get_raw(key) {
            Some(v) => Some(V::from(v)),
            None => None,
        }
    }
}

struct SessionKey;

impl typemap::Key for SessionKey { type Value = Session; }

pub fn auth_required<H: Handler>(handler: H) -> impl Handler {
    move |req: &mut Request| {
        match req.extensions.remove::<AuthConfigKey>() {
            Some(b) => {
                // math b.method {}
                let backend = backends::JWTRedisBackend::with_secret(b.redis_params, b.secret);
                let raw_session = match backend.get_session_from_request(req) {
                    Some(s) => s,
                    None => return Ok(Response::with(status::Unauthorized)),
                };
                let session = Session::new(Box::new(raw_session));
                req.extensions.insert::<SessionKey>(session);
                handler.handle(req)
            },
            None => Ok(Response::with(status::Unauthorized)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
