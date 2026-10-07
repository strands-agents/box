//! The engine loads no compiled-in policy: authored policy alone decides every filesystem path
//! here, and the reach floor in `box` refuses `.strands-box` beneath it (`reach.rs` pins that).

mod support;

use std::path::PathBuf;

use policy::{
    ApprovedPath, FsOperation, GovernedBox, PathResolver, Policy, PolicyEngine, Principal, Request,
};

/// Mint the `ApprovedPath` a `Request::Fs` demands, in the virtual namespace.
fn approved(path: &str) -> ApprovedPath {
    PathResolver::over([PathBuf::from("/Users")])
        .expect("the root is absolute")
        .approve_virtual(std::path::Path::new(path))
        .unwrap_or_else(|refusal| panic!("a fixture path must resolve: {refusal}"))
}

fn catch_all() -> PolicyEngine {
    support::open_policy(vec![Policy {
        origin: PathBuf::from("catch_all.dw"),
        text: r#"permit (principal, action, resource);"#.to_string(),
    }])
    .expect("loads")
}

fn assert_authored_policy_governs(
    policy: &PolicyEngine,
    paths: &[&str],
    operations: &[FsOperation],
) {
    for path in paths {
        for &operation in operations {
            let approved = approved(path);
            let verdict = policy.decide(
                &GovernedBox::assigned("test-box"),
                &Principal::agent(),
                &Request::Fs {
                    path: &approved,
                    operation,
                },
            );
            assert!(
                verdict.is_allow(),
                "the authored catch-all permit must govern {operation:?} on {path}. Got {verdict:?}"
            );
        }
    }
}

#[test]
fn ordinary_filenames_have_no_compiled_authority() {
    assert_authored_policy_governs(
        &catch_all(),
        &[
            "/Users/operator/project/box.toml",
            "/Users/operator/project/policy.dw",
        ],
        &[
            FsOperation::Other,
            FsOperation::WriteContent,
            FsOperation::Rename,
            FsOperation::RemoveFile,
            FsOperation::ExecFile,
            FsOperation::SetPermissions,
            FsOperation::ReadContent,
        ],
    );
}

#[test]
fn policy_authoring_schema_artifacts_remain_under_authored_policy() {
    assert_authored_policy_governs(
        &catch_all(),
        &[
            "/Users/operator/project/.strands-box/actions.cedarschema",
            "/Users/operator/project/.strands-box/events.dwschema",
        ],
        &[
            FsOperation::ReadContent,
            FsOperation::WriteContent,
            FsOperation::Rename,
            FsOperation::RemoveFile,
            FsOperation::Other,
        ],
    );
}

#[test]
fn mcp_schemas_paths_under_the_authority_directory_follow_the_authored_policy() {
    assert_authored_policy_governs(
        &catch_all(),
        &[
            "/Users/operator/project/.strands-box/mcp-schemas",
            "/Users/operator/project/.strands-box/mcp-schemas/issues-mcp.cedarschema",
        ],
        &[
            FsOperation::ReadContent,
            FsOperation::WriteContent,
            FsOperation::Rename,
            FsOperation::RemoveFile,
            FsOperation::RemoveDir,
            FsOperation::Other,
        ],
    );
}
