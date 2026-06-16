pub fn to_rust_dleq(p: psbt_v2::v2::dleq::DleqProof) -> rust_dleq::DleqProof {
    rust_dleq::DleqProof(p.0)
}

pub fn to_psbt_dleq(p: rust_dleq::DleqProof) -> psbt_v2::v2::dleq::DleqProof {
    psbt_v2::v2::dleq::DleqProof(p.0)
}
