extern crate iron;
extern crate serde;
extern crate jsonwebtoken as jwt;
extern crate r2d2_redis;

use iron::prelude::*;
use iron::{typemap, BeforeMiddleware};

trait RawSession {
    fn set_raw(&self, key: &str, value: String);
    fn get_raw(&self, key: &str) -> Option<String>;
}

pub trait AuthBackend: Send + Sync + 'static {
    type S: RawSession;

    fn get_session_from_request(&self, req: &mut Request) -> Self::S;
}

pub struct AuthConfigMiddleware<B: AuthBackend> {
    backend: B,
}

impl<B: AuthBackend> AuthConfigMiddleware<B> {
    pub fn with_secret<B: AuthBackend>(backend: B) -> AuthConfigMiddleware<B> {
        AuthConfigMiddleware { backend }
    }
}

struct BackendKey;
impl typemap::Key for BackendKey { type Value = Box<AuthBackend>; }

impl<B: AuthBackend> BeforeMiddleware for AuthConfigMiddleware<B> {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        req.extensions.insert::<BackendKey>(Box::new(self.backend)).unwrap();
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

    pub fn get<V: From<String>>(self, key: &str, value: V) -> Option<impl V> {
        match self.raw.get_raw() {
            Some(v) => V::from(v),
            None => None,
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
