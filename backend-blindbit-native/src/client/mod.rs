mod client;
mod http_trait;
pub mod structs;
#[cfg(feature = "ureq-client")]
mod ureq_impl;
#[cfg(feature = "reqwest-client")]
mod reqwest_impl;

pub use client::BlindbitClient;
pub use http_trait::HttpClient;

#[cfg(feature = "ureq-client")]
pub use ureq_impl::UreqClient;
#[cfg(feature = "reqwest-client")]
pub use reqwest_impl::ReqwestClient;
