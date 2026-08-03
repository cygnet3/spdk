mod client;
pub mod structs;

mod oracle_grpc {
    tonic::include_proto!("blindbit.oracle.v1");
}

pub use client::BlindbitClient;
