use std::io::Result;

fn main() -> Result<()> {
    let mut prost_build = prost_build::Config::new();
    prost_build.protoc_arg("--experimental_allow_proto3_optional");
    
    // Configure for no_std environment
    prost_build.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    
    prost_build.compile_protos(
        &[
            "src/protos/signature.proto",
            "src/protos/activity.proto",
            "src/protos/inspection.proto",
        ],
        &["src/"],
    )?;
    Ok(())
}
