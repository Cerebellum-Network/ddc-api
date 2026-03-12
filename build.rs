use std::io::Result;

fn main() -> Result<()> {
    let proto_dir = "third_party/ddc-proto/proto";

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
        "activity_tree.PhdTreeNode",
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
    prost_build.type_attribute(
        "activity_tree.NodeTreeLeaf",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.BucketSubTreeLeaf",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.TcaPayload",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.TcaBucketAggregate",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.TcaNodeAggregate",
        "#[derive(Eq, PartialOrd, Ord)]",
    );
    prost_build.type_attribute(
        "activity_tree.PhdPayload",
        "#[derive(Eq, PartialOrd)]",
    );
    prost_build.type_attribute(
        "activity_tree.EhdPayload",
        "#[derive(Eq, PartialOrd)]",
    );
    // Use BTreeMap instead of HashMap for map fields in inspection
    // (required for no_std compatibility since HashMap is not available)
    prost_build.btree_map(&[
        ".inspection.AssignmentTable",
        ".inspection.InspectionState",
        ".inspection.InspectionPathStatus",
    ]);

    prost_build.compile_protos(
        &[
            format!("{proto_dir}/signature/signature.proto"),
            format!("{proto_dir}/auth/token.proto"),
            format!("{proto_dir}/activity/record.proto"),
            format!("{proto_dir}/activity/tree/node.proto"),
            format!("{proto_dir}/activity/tree/bucket.proto"),
            format!("{proto_dir}/activity/tree/tca.proto"),
            format!("{proto_dir}/activity/tree/phd.proto"),
            format!("{proto_dir}/activity/tree/ehd.proto"),
            format!("{proto_dir}/inspection/inspection.proto"),
            format!("{proto_dir}/inspection/challenge.proto"),
            format!("{proto_dir}/era/era.proto"),
        ],
        &[proto_dir],
    )?;
    Ok(())
}
