use std::io::Result;

fn main() -> Result<()> {
    let mut prost_build = prost_build::Config::new();
    prost_build.protoc_arg("--experimental_allow_proto3_optional");

    prost_build.type_attribute(
        "activity_tree.EhdTreeTraversedNode",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.EhdTreeNodeCustomerAggregate",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.EhdTreeNodeProviderAggregate",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.EhdTreeNodeProviderNodeAggregate",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.ActivityNode",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.PhdTreeTraversedNode",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.PhdBucketAggregateGroup",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.PhdNodeAggregateGroup",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.PhdTcaAggregate",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.BucketSubAggregate",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.BucketAggregate",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.BucketAggregatesResponse",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.ActivityTreeTraversedNode",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.ActivityTreeTraversalResponse",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.compile_protos(
        &[
            "src/protos/signature.proto",
            "src/protos/activity.proto",
            "src/protos/inspection.proto",
            "src/protos/activity_tree.proto",
        ],
        &["src/"],
    )?;
    Ok(())
}
