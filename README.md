iron-auth [![Build Status](https://travis-ci.org/Arekkusuva/iron-auth.svg?branch=master)](https://travis-ci.org/Arekkusuva/iron-auth)
==========

> Under development!

> Authentication middleware for the [Iron](https://github.com/iron/iron) web framework.

It allows you to wrap iron routes to protect it and store data in a session for each user.

## Example

```rust
extern crate iron;
extern crate router;
extern crate iron_auth;

use iron::prelude::*;
use iron::status;
use router::Router;
use iron_auth::{AuthConfigMiddleware, AuthWrapper, Claims, AuthReqExt};

fn without_token(req: &mut Request) -> IronResult<Response> {
    Ok(Response::with((status::Ok, "Public info")))
}

fn with_token(req: &mut Request) -> IronResult<Response> {
    let session = req.session().unwrap();
    let claims = session.get_claims();
    // let new_token = req.create_token(Claims { ... }).unwrap();
    // ...
    Ok(Response::with((status::Ok, "Private info")))
}

fn main() {
    let mut router = Router::new();
    router.get("/without_token", AuthWrapper::wrap(without_token), "without_token");
    router.get("/with_token", AuthWrapper::wrap(with_token), "with_token");

    let mut chain = Chain::new(router);
    chain.link_before(AuthConfigMiddleware::new(
        "secret".to_string(),
        "redis://localhost",
    ));

    Iron::new(chain).http("localhost:8000").unwrap();
}
```
