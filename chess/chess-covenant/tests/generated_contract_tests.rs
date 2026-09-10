use std::collections::BTreeSet;

use argent_artifact::{Artifact, TypeArtifact};
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_txscript::parse_script;

struct SizeSnapshot {
    actor: &'static str,
    expected_script_len: usize,
    expected_instruction_count: usize,
    expected_charged_op_count: usize,
    baseline_script_len: usize,
    baseline_instruction_count: usize,
    baseline_charged_op_count: usize,
}

fn artifact() -> Artifact {
    let artifact: Artifact =
        serde_json::from_str(include_str!("../../build/artifact.json")).expect("pinned chess artifact deserializes");
    artifact.check_consistency().expect("chess artifact is consistent");
    artifact
}

fn script_op_counts(script: &[u8]) -> (usize, usize) {
    let mut instruction_count = 0;
    let mut charged_op_count = 0;
    for opcode in parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(script) {
        let opcode = opcode.expect("compiled script parses");
        instruction_count += 1;
        if !opcode.is_push_opcode() {
            charged_op_count += 1;
        }
    }
    (instruction_count, charged_op_count)
}

fn size_snapshots() -> [SizeSnapshot; 12] {
    // Baseline values are frozen measurements of the handwritten contracts.
    // The test reads only the generated artifact.
    [
        SizeSnapshot {
            actor: "League",
            expected_script_len: 639,
            expected_instruction_count: 410,
            expected_charged_op_count: 290,
            baseline_script_len: 488,
            baseline_instruction_count: 289,
            baseline_charged_op_count: 213,
        },
        SizeSnapshot {
            actor: "Player",
            expected_script_len: 3723,
            expected_instruction_count: 2652,
            expected_charged_op_count: 1766,
            baseline_script_len: 3456,
            baseline_instruction_count: 2550,
            baseline_charged_op_count: 1660,
        },
        SizeSnapshot {
            actor: "Mux",
            expected_script_len: 2253,
            expected_instruction_count: 1439,
            expected_charged_op_count: 979,
            baseline_script_len: 1754,
            baseline_instruction_count: 1086,
            baseline_charged_op_count: 736,
        },
        SizeSnapshot {
            actor: "Settle",
            expected_script_len: 2982,
            expected_instruction_count: 2207,
            expected_charged_op_count: 1458,
            baseline_script_len: 2656,
            baseline_instruction_count: 2068,
            baseline_charged_op_count: 1347,
        },
        SizeSnapshot {
            actor: "Pawn",
            expected_script_len: 2029,
            expected_instruction_count: 1328,
            expected_charged_op_count: 876,
            baseline_script_len: 1972,
            baseline_instruction_count: 1332,
            baseline_charged_op_count: 872,
        },
        SizeSnapshot {
            actor: "Knight",
            expected_script_len: 1620,
            expected_instruction_count: 951,
            expected_charged_op_count: 625,
            baseline_script_len: 1496,
            baseline_instruction_count: 891,
            baseline_charged_op_count: 594,
        },
        SizeSnapshot {
            actor: "Vert",
            expected_script_len: 2153,
            expected_instruction_count: 1450,
            expected_charged_op_count: 985,
            baseline_script_len: 2104,
            baseline_instruction_count: 1469,
            baseline_charged_op_count: 1011,
        },
        SizeSnapshot {
            actor: "Horiz",
            expected_script_len: 2152,
            expected_instruction_count: 1449,
            expected_charged_op_count: 985,
            baseline_script_len: 2104,
            baseline_instruction_count: 1469,
            baseline_charged_op_count: 1011,
        },
        SizeSnapshot {
            actor: "Diag",
            expected_script_len: 2160,
            expected_instruction_count: 1470,
            expected_charged_op_count: 1004,
            baseline_script_len: 2071,
            baseline_instruction_count: 1443,
            baseline_charged_op_count: 993,
        },
        SizeSnapshot {
            actor: "King",
            expected_script_len: 1692,
            expected_instruction_count: 1007,
            expected_charged_op_count: 666,
            baseline_script_len: 1582,
            baseline_instruction_count: 958,
            baseline_charged_op_count: 637,
        },
        SizeSnapshot {
            actor: "Castle",
            expected_script_len: 1685,
            expected_instruction_count: 1039,
            expected_charged_op_count: 678,
            baseline_script_len: 1630,
            baseline_instruction_count: 1019,
            baseline_charged_op_count: 670,
        },
        SizeSnapshot {
            actor: "CastleChallengePrep",
            expected_script_len: 1854,
            expected_instruction_count: 1200,
            expected_charged_op_count: 792,
            baseline_script_len: 1729,
            baseline_instruction_count: 1120,
            baseline_charged_op_count: 733,
        },
    ]
}

#[test]
fn generated_artifact_contains_the_complete_chess_application() {
    let artifact = artifact();
    let actors = artifact.argent.actors.iter().map(|actor| actor.name.as_str()).collect::<Vec<_>>();
    let contracts = artifact.sil_abi.contracts.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected =
        ["League", "Player", "Mux", "Pawn", "Knight", "Vert", "Horiz", "Diag", "King", "Castle", "CastleChallengePrep", "Settle"];

    assert_eq!(actors, expected);
    assert_eq!(contracts, expected.into_iter().collect());
}

#[test]
fn generated_artifact_uses_compact_chess_state_fields() {
    let artifact = artifact();
    let game = artifact.argent.states.iter().find(|state| state.name == "GameState").expect("GameState exists");
    assert_eq!(
        game.fields.iter().map(|field| (field.name.as_str(), field.ty.clone())).collect::<Vec<_>>(),
        [
            ("white_player", TypeArtifact::FixedBytes { len: 32 }),
            ("black_player", TypeArtifact::FixedBytes { len: 32 }),
            ("board", TypeArtifact::FixedBytes { len: 64 }),
            ("turn", TypeArtifact::Byte),
            ("status", TypeArtifact::Byte),
            ("move_timeout", TypeArtifact::Int),
            ("castle_rights", TypeArtifact::FixedBytes { len: 4 }),
            ("en_passant_idx", TypeArtifact::Byte),
            ("pending_src_idx", TypeArtifact::Byte),
            ("pending_dst_idx", TypeArtifact::Byte),
            ("pending_promo", TypeArtifact::Byte),
            ("recent_castle", TypeArtifact::Byte),
            ("draw_state", TypeArtifact::Byte),
        ]
    );
    let authored_size = game
        .fields
        .iter()
        .map(|field| match &field.ty {
            TypeArtifact::Byte => 1,
            TypeArtifact::Int => 8,
            TypeArtifact::FixedBytes { len } => *len,
            ty => panic!("unexpected GameState field type {ty:?}"),
        })
        .sum::<usize>();
    assert_eq!(authored_size, 148);

    let settle = artifact.argent.states.iter().find(|state| state.name == "SettleState").expect("SettleState exists");
    let status = settle.fields.last().expect("SettleState has a status field");
    assert_eq!(status.name, "status");
    assert_eq!(status.ty, TypeArtifact::Byte);
}

#[test]
fn generated_contract_sizes_match_snapshots() {
    let artifact = artifact();
    let mut actual = Vec::new();
    for snapshot in size_snapshots() {
        let contract = artifact.sil_abi.contract(snapshot.actor).expect("snapshot actor has a compiled contract");
        let script = &contract.compiled.bytecode;
        let (instruction_count, charged_op_count) = script_op_counts(script);
        actual.push((snapshot, script.len(), instruction_count, charged_op_count));
    }

    for (snapshot, script_len, instruction_count, charged_op_count) in &actual {
        eprintln!(
            "{}: generated={}/{}/{} baseline={}/{}/{} delta={:+}/{:+}/{:+}",
            snapshot.actor,
            script_len,
            instruction_count,
            charged_op_count,
            snapshot.baseline_script_len,
            snapshot.baseline_instruction_count,
            snapshot.baseline_charged_op_count,
            *script_len as isize - snapshot.baseline_script_len as isize,
            *instruction_count as isize - snapshot.baseline_instruction_count as isize,
            *charged_op_count as isize - snapshot.baseline_charged_op_count as isize
        );
    }

    for (snapshot, script_len, instruction_count, charged_op_count) in actual {
        assert_eq!(script_len, snapshot.expected_script_len, "{} script length changed", snapshot.actor);
        assert_eq!(instruction_count, snapshot.expected_instruction_count, "{} instruction count changed", snapshot.actor);
        assert_eq!(charged_op_count, snapshot.expected_charged_op_count, "{} charged operation count changed", snapshot.actor);
    }
}
