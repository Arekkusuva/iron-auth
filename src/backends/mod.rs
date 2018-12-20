use iron::prelude::*;
use iron::headers::{Authorization, Bearer};
use r2d2_redis::RedisConnectionManager;
use r2d2_redis::r2d2::Pool;
use r2d2_redis::redis::IntoConnectionInfo;
use jwt;

use super::{AuthSessionBackend, RawSession};

type RedisPool = Pool<RedisConnectionManager>;

pub struct RedisSession {
    session_id: String,
    pool: RedisPool,
}

impl RawSession for RedisSession {
    fn set_raw(&self, _key: &str, _value: String) {
        unimplemented!()
    }

    fn get_raw(&self, _key: &str) -> Option<String> {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct JWTRedisBackend {
    secret: String,
    pool: RedisPool,
}

impl JWTRedisBackend {
    pub fn with_secret<P: IntoConnectionInfo>(params: P, secret: String) -> JWTRedisBackend {
        let manager = RedisConnectionManager::new(params).unwrap();
        let pool = Pool::builder()
            .build(manager)
            .unwrap();

        JWTRedisBackend {
            secret,
            pool,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    pub user_id: u64,
    pub exp: usize,
}

impl AuthSessionBackend for JWTRedisBackend {
    type S = RedisSession;

    fn get_session_from_request(&self, req: &mut Request) -> Option<Self::S> {
        let token = match req.headers.get::<Authorization<Bearer>>() {
            Some(b) => b.token.clone(),
            None => return None,
        };

        let claims: Claims = match jwt::decode(&token, self.secret.as_bytes(), &jwt::Validation::default()) {
            Ok(t) => t.claims,
            Err(_) => return None,
        };

        let session_id: String = token.rsplitn(2, ".").collect();

        Some(RedisSession {
            session_id,
            pool: self.pool.clone(),
        })
    }
}
