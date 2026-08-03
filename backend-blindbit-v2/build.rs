fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &["proto/oracle_service.proto", "proto/indexing_server.proto"],
            &["proto"],
        )?;
    Ok(())
}
