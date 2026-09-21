//! Conformance replay -- the published IQA vector set, executed against THIS build.
//!
//! The vectors ship inside the crate (`vectors/iqa-conformance-v1.2.6.json`).
//! Every published check is replayed:
//!   8 positive URIs + 18 fail-closed rejections + 5 action-safety rows
//!   + 3 closed-set checks (organ / action / standing, RFC-009 sec. 10.1)
//!   + 1 domain-prefix check
//!   + 3 envelope checks (canonical signing input, AID self-certification,
//!     Ed25519 signature).
//!
//! **Nothing may be skipped silently.** A zero-dependency build cannot do the
//! Ed25519 arithmetic, so that one check is reported as `skipped` and counted --
//! the tests below assert `checked + skipped == PUBLISHED_CHECKS`, so no check
//! can disappear from the report by accident.
//!
//! The closed sets are read from the vector and compared with this crate's own
//! constants. RFC-009 sec. 10.1 freezes them, so an implementation whose set
//! drifted must fail here out loud instead of quietly passing its own tests.

use crate::iqa_uri;
use crate::json::{parse as json_parse, Json};
use crate::sha256::{bytes_to_hex, hex_to_bytes, sha256};

/// The domain separation prefix of SPEC/IQA-URI-ATTEST-v1.2.6 sec. 5.2.
pub const DOMAIN: &[u8] = b"iqa-attest-v1\n";

/// Checks the published vector set contains in total.
pub const PUBLISHED_CHECKS: usize = 38;

/// Checks a build without the `ed25519` feature can execute -- 38 minus the
/// signature arithmetic.
pub const CHECKS_WITHOUT_PRIMITIVE: usize = 37;

#[derive(Debug, Clone)]
pub struct ConformanceResult {
    pub checked: usize,
    pub passed: usize,
    /// Checks this build could not run (optional primitive absent). Always
    /// visible in the count -- never a quiet zero.
    pub skipped: usize,
    pub failures: Vec<String>,
}

impl ConformanceResult {
    /// One-line summary, same shape the Python and JavaScript packages print.
    pub fn summary(&self) -> String {
        if !self.failures.is_empty() {
            format!(
                "[FAIL] {} of {} checks failed ({} skipped)",
                self.failures.len(),
                self.checked,
                self.skipped
            )
        } else if self.skipped > 0 {
            format!(
                "[PASS] all {} checks passed ({} skipped)",
                self.checked, self.skipped
            )
        } else {
            format!("[PASS] all {} checks passed", self.checked)
        }
    }
}

fn opt_str(j: Option<&Json>) -> Option<&str> {
    match j {
        Some(Json::Str(s)) => Some(s),
        _ => None,
    }
}

/// Compare a published JSON array of strings with this crate's closed set.
fn same_closed_set(published: &Json, ours: &[&str]) -> bool {
    let Some(items) = published.as_arr() else {
        return false;
    };
    let mut theirs: Vec<&str> = Vec::new();
    for item in items {
        match opt_str(Some(item)) {
            Some(s) => theirs.push(s),
            None => return false,
        }
    }
    theirs.sort_unstable();
    let mut ours_sorted: Vec<&str> = ours.to_vec();
    ours_sorted.sort_unstable();
    theirs == ours_sorted
}

/// Replay a parsed vector document.
pub fn run(doc: &Json) -> ConformanceResult {
    let mut res = ConformanceResult {
        checked: 0,
        passed: 0,
        skipped: 0,
        failures: Vec::new(),
    };
    let check = |res: &mut ConformanceResult, ok: bool, label: &str, detail: String| {
        res.checked += 1;
        if ok {
            res.passed += 1;
        } else {
            res.failures.push(format!("{}: {}", label, detail));
        }
    };

    // --- positive URIs ------------------------------------------------------
    if let Some(cases) = doc.get("positive_uris").and_then(Json::as_arr) {
        for case in cases {
            let uri = opt_str(case.get("uri")).unwrap_or("");
            match iqa_uri::parse(uri) {
                Err(e) => check(
                    &mut res,
                    false,
                    uri,
                    format!("expected ACCEPT, rejected: {}", e),
                ),
                Ok(p) => {
                    let mut bad: Vec<String> = Vec::new();
                    if p.canonical_uri != opt_str(case.get("canonical_uri")).unwrap_or("") {
                        bad.push(format!(
                            "canonical_uri {:?} != {:?}",
                            p.canonical_uri,
                            opt_str(case.get("canonical_uri"))
                        ));
                    }
                    if p.subject_is_hash
                        != case
                            .get("subject_is_hash")
                            .and_then(Json::as_bool)
                            .unwrap_or(false)
                    {
                        bad.push("subject_is_hash".into());
                    }
                    if p.organ != opt_str(case.get("organ")).unwrap_or("") {
                        bad.push("organ".into());
                    }
                    if p.root != opt_str(case.get("root")).unwrap_or("") {
                        bad.push("root".into());
                    }
                    if p.authority != opt_str(case.get("authority")).unwrap_or("") {
                        bad.push("authority".into());
                    }
                    let want_action = opt_str(case.get("action"));
                    if p.action.as_deref() != want_action {
                        bad.push(format!("action {:?} != {:?}", p.action, want_action));
                    }
                    if p.action_omitted
                        != case
                            .get("action_omitted")
                            .and_then(Json::as_bool)
                            .unwrap_or(false)
                    {
                        bad.push("action_omitted".into());
                    }
                    if p.action_safe
                        != case
                            .get("action_safe")
                            .and_then(Json::as_bool)
                            .unwrap_or(false)
                    {
                        bad.push("action_safe".into());
                    }
                    if p.route_hex != opt_str(case.get("route_hex")).unwrap_or("") {
                        bad.push(format!(
                            "route_hex {:?} != {:?}",
                            p.route_hex,
                            opt_str(case.get("route_hex"))
                        ));
                    }
                    check(&mut res, bad.is_empty(), uri, bad.join("; "));
                }
            }
        }
    }

    // --- negative URIs ------------------------------------------------------
    if let Some(cases) = doc.get("negative_uris").and_then(Json::as_arr) {
        for case in cases {
            let uri = opt_str(case.get("uri")).unwrap_or("");
            check(
                &mut res,
                iqa_uri::parse(uri).is_err(),
                uri,
                "expected REJECT but parsed".into(),
            );
        }
    }

    // --- closed sets: RFC-009 sec. 10.1 freezes all three --------------------
    for (key, ours, label) in [
        (
            "organ_closed_set",
            &iqa_uri::ORGANS[..],
            "closed set: organ",
        ),
        (
            "action_closed_set",
            &iqa_uri::ACTIONS[..],
            "closed set: action",
        ),
        (
            "standings_closed_set",
            &iqa_uri::STANDINGS[..],
            "closed set: standing",
        ),
    ] {
        let ok = doc
            .get(key)
            .map(|j| same_closed_set(j, ours))
            .unwrap_or(false);
        check(
            &mut res,
            ok,
            label,
            format!("the published {} disagrees with this crate", key),
        );
    }

    // --- sec. 11.3 safety classes ----------------------------------------------
    if let Some(rows) = doc.get("action_safety").and_then(Json::as_arr) {
        for row in rows {
            let action = opt_str(row.get("action"));
            let uri = match action {
                Some(a) => format!("iqa://3f9a1b2c.gateway.iqa/{}", a),
                None => "iqa://3f9a1b2c.gateway.iqa".to_string(),
            };
            let want = row.get("safe").and_then(Json::as_bool).unwrap_or(false);
            match iqa_uri::parse(&uri) {
                Err(e) => check(
                    &mut res,
                    false,
                    &format!("action_safety {:?}", action),
                    format!("expected ACCEPT, rejected: {}", e),
                ),
                Ok(p) => check(
                    &mut res,
                    p.action_safe == want,
                    &format!("action_safety {:?}", action),
                    format!("action_safe {} != {}", p.action_safe, want),
                ),
            }
        }
    }

    // --- deterministic attestation envelope ---------------------------------
    if let Some(env) = doc.get("attest_envelope_vector") {
        // Domain prefix first: the published bytes must be the ones this build
        // puts in front of every signing input.
        let want_prefix = opt_str(env.get("domain_prefix_hex")).unwrap_or("");
        let want_input = opt_str(env.get("signing_input_hex")).unwrap_or("");
        let got_prefix = bytes_to_hex(DOMAIN);
        check(
            &mut res,
            !want_prefix.is_empty()
                && got_prefix == want_prefix
                && want_input.starts_with(&got_prefix),
            "envelope domain prefix",
            format!(
                "{:?} != {:?}, or not a prefix of the signing input",
                want_prefix, got_prefix
            ),
        );

        let body = Json::Obj(vec![
            ("alg".into(), env.get("alg").cloned().unwrap_or(Json::Null)),
            ("aid".into(), env.get("aid").cloned().unwrap_or(Json::Null)),
            (
                "nonce".into(),
                env.get("nonce").cloned().unwrap_or(Json::Null),
            ),
            (
                "payload".into(),
                env.get("payload").cloned().unwrap_or(Json::Null),
            ),
            ("pub".into(), env.get("pub").cloned().unwrap_or(Json::Null)),
            ("ts".into(), env.get("ts").cloned().unwrap_or(Json::Null)),
        ]);
        let mut input = DOMAIN.to_vec();
        input.extend_from_slice(body.canonical().as_bytes());
        check(
            &mut res,
            bytes_to_hex(&input) == want_input,
            "envelope signing input",
            "canonical signing input differs from the published vector".into(),
        );

        let pub_hex = opt_str(env.get("pub")).unwrap_or("");
        let aid_ok = hex_to_bytes(pub_hex)
            .map(|p| bytes_to_hex(&sha256(&p)) == opt_str(env.get("aid")).unwrap_or(""))
            .unwrap_or(false);
        check(
            &mut res,
            aid_ok,
            "envelope AID self-certification",
            "aid != SHA-256(pub)".into(),
        );

        #[cfg(feature = "ed25519")]
        {
            // The vector is pinned to a fixed ts, so the freshness window is
            // deliberately not enforced here.
            let ts = env.get("ts").and_then(Json::as_u128).unwrap_or(0) as u64;
            let v = crate::attest::verify_envelope(env, Some(ts), false);
            check(
                &mut res,
                v.is_ok(),
                "envelope Ed25519 signature",
                v.err().map(|e| e.0).unwrap_or_default(),
            );
        }
        #[cfg(not(feature = "ed25519"))]
        {
            // Reported, not hidden: the count is asserted by the tests below.
            res.skipped += 1;
        }
    }

    res
}

/// Convenience: parse the shipped vector file and replay it.
pub fn run_shipped() -> ConformanceResult {
    match json_parse(include_str!("../vectors/iqa-conformance-v1.2.6.json")) {
        Ok(doc) => run(&doc),
        Err(e) => ConformanceResult {
            checked: 1,
            passed: 0,
            skipped: 0,
            failures: vec![format!("cannot parse shipped vectors: {}", e)],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_vectors_replay_green() {
        let r = run_shipped();
        println!("{}", r.summary());
        assert!(r.failures.is_empty(), "failures: {:?}", r.failures);
        assert_eq!(
            r.checked + r.skipped,
            PUBLISHED_CHECKS,
            "the whole published vector set must be replayed -- nothing may vanish silently"
        );
        assert_eq!(
            r.checked,
            CHECKS_WITHOUT_PRIMITIVE + usize::from(cfg!(feature = "ed25519")),
            "only the Ed25519 primitive itself may be skipped in the default build"
        );
        assert_eq!(r.checked, r.passed);
    }
}
