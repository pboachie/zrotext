// SPDX-License-Identifier: AGPL-3.0-only
//! Structured EXPLAIN assertions shared by the populated PostgreSQL regression.
use serde_json::{Value, json};
use tokio_postgres::{
    Client,
    types::{FromSql, Type},
};
use uuid::Uuid;

// EXPLAIN FORMAT JSON returns PostgreSQL's json type (UTF-8 text), not jsonb.
// Decode it locally without adding a feature/dependency to the runtime client.
#[derive(Debug)]
struct JsonPlan(Value);
impl<'a> FromSql<'a> for JsonPlan {
    fn from_sql(_: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        Ok(Self(serde_json::from_slice(raw)?))
    }
    fn accepts(ty: &Type) -> bool {
        *ty == Type::JSON
    }
}

pub(super) async fn explain_queue(db: &Client, account: Uuid) -> Value {
    db.query_one(
        &format!(
            "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {}",
            crate::enrollment::OWNER_DEVICE_STATUS_QUERY
        ),
        &[&account, &None::<Uuid>, &51_i64, &1_000_i64],
    )
    .await
    .unwrap()
    .get::<_, JsonPlan>(0)
    .0
}

// The sparse fixture has two tenants with three entries each in the in-flight
// partial index. Filtering those six active entries is harmless; filtering the
// 200,000 delivered entries is not. Also bound bitmap construction, not just the
// resulting heap rows. The populated/capped validator below remains stricter.
pub(super) fn validate_sparse_history_plan(plan: &Value) -> Result<(), &'static str> {
    fn counter(node: &Value, field: &str, optional: bool) -> Result<f64, &'static str> {
        let value = match node.get(field) {
            None if optional => return Ok(0.0), // PostgreSQL omits unused filter counters.
            value => value
                .and_then(Value::as_f64)
                .ok_or("missing or invalid sparse counter")?,
        };
        if !value.is_finite() || value < 0.0 || value.fract() != 0.0 {
            return Err("sparse work counter is not a finite nonnegative integer");
        }
        Ok(value)
    }
    fn bounded_inputs(
        node: &Value,
        total: &mut f64,
        device_index: &mut bool,
    ) -> Result<(), &'static str> {
        let kind = node["Node Type"]
            .as_str()
            .ok_or("missing sparse node type")?;
        if counter(node, "Actual Loops", false)? != 1.0 {
            return Err("sparse probe must execute once");
        }
        if kind == "Seq Scan" {
            return Err("sparse queue scanned message history");
        }
        if matches!(
            kind,
            "Index Scan" | "Index Only Scan" | "Bitmap Heap Scan" | "Bitmap Index Scan"
        ) {
            let work = counter(node, "Actual Rows", false)?
                + counter(node, "Rows Removed by Filter", true)?
                + counter(node, "Rows Removed by Index Recheck", true)?;
            if work > 6.0 || counter(node, "Lossy Heap Blocks", true)? != 0.0 {
                return Err("sparse index input exceeds the six active fixture rows");
            }
            *total += work;
            // A bitmap intersection may inspect two six-entry inputs plus six
            // heap entries. Bound their combined work as well as every input.
            if *total > 18.0 {
                return Err("sparse probe has excessive combined index work");
            }
        } else if matches!(kind, "BitmapAnd" | "BitmapOr") {
            // PostgreSQL reports zero output rows for bitmap combiners. Their
            // leaf inputs above carry the actual work, but the counter must
            // still be a valid number rather than malformed/missing data.
            counter(node, "Actual Rows", false)?;
        } else {
            return Err("unsupported node in sparse message-index subtree");
        }
        if node["Index Name"] == "messages_device_state" {
            *device_index = true;
        }
        if let Some(children) = node.get("Plans") {
            for child in children.as_array().ok_or("invalid sparse plan children")? {
                bounded_inputs(child, total, device_index)?;
            }
        }
        Ok(())
    }
    fn visit(node: &Value, rows: &mut Vec<f64>) -> Result<(), &'static str> {
        if node["Relation Name"] == "messages" {
            let actual = counter(node, "Actual Rows", false)?;
            let mut device_index = false;
            let mut work = 0.0;
            bounded_inputs(node, &mut work, &mut device_index)?;
            match node["Node Type"].as_str() {
                Some("Index Scan" | "Index Only Scan")
                    if node["Index Name"] == "messages_device_state"
                        || (actual == 2.0
                            && node["Index Name"] == "messages_in_flight_updated") => {}
                Some("Bitmap Heap Scan") if device_index => {}
                _ => return Err("sparse probe has no supported bounded index path"),
            }
            rows.push(actual);
            return Ok(()); // Its entire message-index subtree was accounted above.
        }
        if let Some(children) = node.get("Plans") {
            for child in children.as_array().ok_or("invalid sparse plan children")? {
                visit(child, rows)?;
            }
        }
        Ok(())
    }
    let roots = plan.as_array().ok_or("invalid sparse EXPLAIN document")?;
    if roots.len() != 1 {
        return Err("expected exactly one sparse EXPLAIN plan");
    }
    let root = roots[0].get("Plan").ok_or("missing sparse root")?;
    let mut rows = Vec::new();
    visit(root, &mut rows)?;
    rows.sort_by(f64::total_cmp);
    if rows != [2.0, 3.0] {
        return Err("sparse queue must read only its two active-state sets");
    }
    Ok(())
}

pub(super) fn validate_queue_plan(plan: &Value, expected_rows: &[f64]) -> Result<(), &'static str> {
    fn visit(
        node: &Value,
        parent: Option<&Value>,
        scans: &mut Vec<f64>,
    ) -> Result<(), &'static str> {
        if node["Relation Name"] == "messages" {
            if !matches!(
                node["Node Type"].as_str(),
                Some("Index Scan" | "Index Only Scan")
            ) || node["Index Name"] != "messages_device_state"
            {
                return Err("messages must use the device-state index, never a history scan");
            }
            let rows = node["Actual Rows"]
                .as_f64()
                .ok_or("missing actual scan rows")?;
            if !(0.0..=1_000.0).contains(&rows) || node["Actual Loops"].as_f64() != Some(1.0) {
                return Err("message index work exceeds one bounded probe");
            }
            for field in ["Rows Removed by Filter", "Rows Removed by Index Recheck"] {
                if node
                    .get(field)
                    .is_some_and(|value| value.as_f64() != Some(0.0))
                {
                    return Err("message probe filtered historical or unrelated rows");
                }
            }
            let parent = parent.ok_or("message scan has no limiting parent")?;
            if parent["Node Type"] != "Limit"
                || parent["Actual Rows"].as_f64() != Some(rows)
                || parent["Actual Loops"].as_f64() != Some(1.0)
            {
                return Err("message scan must feed its bounded limit directly");
            }
            scans.push(rows);
        }
        if let Some(children) = node.get("Plans") {
            for child in children.as_array().ok_or("invalid plan children")? {
                visit(child, Some(node), scans)?;
            }
        }
        Ok(())
    }
    let roots = plan.as_array().ok_or("invalid EXPLAIN document")?;
    if roots.len() != 1 {
        return Err("expected exactly one EXPLAIN plan");
    }
    let root = roots[0].get("Plan").ok_or("missing root plan")?;
    let mut scans = Vec::new();
    visit(root, None, &mut scans)?;
    scans.sort_by(f64::total_cmp);
    if scans.len() != 2 || scans != expected_rows {
        return Err("expected two independent queue probes with exact actual counts");
    }
    Ok(())
}

fn synthetic_plan(rows: Value, loops: Value) -> Value {
    let scan = json!({"Node Type":"Index Scan", "Relation Name":"messages",
        "Index Name":"messages_device_state", "Actual Rows":rows, "Actual Loops":loops});
    let limit =
        json!({"Node Type":"Limit", "Actual Rows":rows, "Actual Loops":loops, "Plans":[scan]});
    json!([{"Plan":{"Node Type":"CTE Scan", "Plans":[limit.clone(), limit]}}])
}

#[test]
fn json_plan_numbers_accept_integer_and_fractional_postgres_representations() {
    for (rows, loops) in [(json!(1000), json!(1)), (json!(1000.00), json!(1.00))] {
        let plan = synthetic_plan(rows, loops);
        let encoded = serde_json::to_vec(&plan).unwrap();
        let decoded = JsonPlan::from_sql(&Type::JSON, &encoded).unwrap().0;
        assert_eq!(validate_queue_plan(&decoded, &[1000.0, 1000.0]), Ok(()));
    }
    assert!(JsonPlan::accepts(&Type::JSON));
    assert!(!JsonPlan::accepts(&Type::JSONB));
}

#[test]
fn json_plan_assertions_reject_history_scans_unbounded_work_and_missing_probes() {
    for (field, value) in [
        ("Node Type", json!("Seq Scan")),
        ("Index Name", json!("messages_pkey")),
        ("Actual Rows", json!(1001.0)),
        ("Actual Rows", json!("1000")),
        ("Actual Loops", json!(2.0)),
        ("Rows Removed by Filter", json!(200000)),
        ("Rows Removed by Index Recheck", json!(1)),
        ("Relation Name", json!("other")),
    ] {
        let mut plan = synthetic_plan(json!(1000), json!(1));
        plan[0]["Plan"]["Plans"][0]["Plans"][0][field] = value;
        assert!(
            validate_queue_plan(&plan, &[1000.0, 1000.0]).is_err(),
            "{field}"
        );
    }
    let mut no_limit = synthetic_plan(json!(1000), json!(1));
    no_limit[0]["Plan"]["Plans"][0]["Node Type"] = json!("Sort");
    assert!(validate_queue_plan(&no_limit, &[1000.0, 1000.0]).is_err());
    let mut missing = synthetic_plan(json!(1000), json!(1));
    missing[0]["Plan"]["Plans"].as_array_mut().unwrap().pop();
    assert!(validate_queue_plan(&missing, &[1000.0, 1000.0]).is_err());
}

#[test]
fn sparse_history_allows_small_bitmap_probes_but_rejects_history_filtering() {
    let mut plan = synthetic_plan(json!(3), json!(1));
    plan[0]["Plan"]["Plans"][1]["Plans"][0]["Actual Rows"] = json!(2.0);
    let scan = &mut plan[0]["Plan"]["Plans"][1]["Plans"][0];
    scan["Node Type"] = json!("Bitmap Heap Scan");
    scan.as_object_mut().unwrap().remove("Index Name");
    scan["Plans"] = json!([{"Node Type":"Bitmap Index Scan", "Index Name":"messages_device_state",
        "Actual Rows":2, "Actual Loops":1}]);
    assert_eq!(validate_sparse_history_plan(&plan), Ok(()));
    plan[0]["Plan"]["Plans"][1]["Plans"][0]["Rows Removed by Filter"] = json!(200000);
    assert!(validate_sparse_history_plan(&plan).is_err());
    plan[0]["Plan"]["Plans"][1]["Plans"][0]["Rows Removed by Filter"] = json!(0);
    plan[0]["Plan"]["Plans"][1]["Plans"][0]["Node Type"] = json!("Seq Scan");
    assert!(validate_sparse_history_plan(&plan).is_err());
}

// Synthetic projection of PostgreSQL's sparse partial-index plan, with no
// tenant identifiers or captured operational plan data in the fixture.
fn sparse_partial_plan() -> Value {
    let pending = json!({"Node Type":"Index Scan", "Relation Name":"messages",
        "Index Name":"messages_device_state", "Actual Rows":3.00,"Actual Loops":1,
        "Rows Removed by Filter":0,"Rows Removed by Index Recheck":0});
    let in_flight = json!({"Node Type":"Index Scan", "Relation Name":"messages",
        "Index Name":"messages_in_flight_updated", "Actual Rows":2.00,"Actual Loops":1,
        "Rows Removed by Filter":4});
    json!([{"Plan":{"Node Type":"CTE Scan","Plans":[
        {"Node Type":"Limit","Actual Rows":3,"Actual Loops":1,"Plans":[pending]},
        {"Node Type":"Limit","Actual Rows":2,"Actual Loops":1,"Plans":[
            {"Node Type":"Sort","Actual Rows":2,"Actual Loops":1,"Plans":[in_flight]}]}
    ]}}])
}

#[test]
fn sparse_partial_index_can_filter_only_the_bounded_active_fixture() {
    assert_eq!(validate_sparse_history_plan(&sparse_partial_plan()), Ok(()));
    for (field, value) in [
        ("Rows Removed by Filter", json!(5)),
        ("Rows Removed by Filter", json!(200000)),
        ("Rows Removed by Index Recheck", json!(1)),
        ("Actual Loops", json!(2)),
        ("Actual Rows", json!(-1)),
        ("Actual Rows", json!(2.5)),
        ("Actual Rows", json!("NaN")),
        ("Rows Removed by Filter", json!(null)),
        ("Rows Removed by Filter", json!(-1)),
        ("Index Name", json!("messages_pkey")),
        ("Node Type", json!("Seq Scan")),
    ] {
        let mut plan = sparse_partial_plan();
        plan[0]["Plan"]["Plans"][1]["Plans"][0]["Plans"][0][field] = value;
        assert!(validate_sparse_history_plan(&plan).is_err(), "{field}");
    }
    for field in ["Actual Rows", "Actual Loops"] {
        let mut plan = sparse_partial_plan();
        plan[0]["Plan"]["Plans"][1]["Plans"][0]["Plans"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(validate_sparse_history_plan(&plan).is_err(), "{field}");
    }
    // The sparse exception never applies to the populated capped validator.
    assert!(validate_queue_plan(&sparse_partial_plan(), &[2.0, 3.0]).is_err());
}

#[test]
fn sparse_bitmap_work_includes_every_input_not_only_heap_output() {
    let mut plan = sparse_partial_plan();
    let heap = &mut plan[0]["Plan"]["Plans"][1]["Plans"][0]["Plans"][0];
    heap["Node Type"] = json!("Bitmap Heap Scan");
    heap["Rows Removed by Filter"] = json!(0);
    heap.as_object_mut().unwrap().remove("Index Name");
    heap["Plans"] = json!([{"Node Type":"BitmapAnd", "Actual Rows":0,"Actual Loops":1,"Plans":[
        {"Node Type":"Bitmap Index Scan","Index Name":"messages_device_state","Actual Rows":6,"Actual Loops":1},
        {"Node Type":"Bitmap Index Scan","Index Name":"messages_account_created","Actual Rows":6,"Actual Loops":1}
    ]}]);
    assert_eq!(validate_sparse_history_plan(&plan), Ok(()));
    for (field, value) in [
        ("Actual Rows", json!(200000)),
        ("Actual Loops", json!(2)),
        ("Actual Rows", json!(-1)),
        ("Actual Rows", json!("Infinity")),
    ] {
        let mut bad = plan.clone();
        bad[0]["Plan"]["Plans"][1]["Plans"][0]["Plans"][0]["Plans"][0]["Plans"][1][field] = value;
        assert!(validate_sparse_history_plan(&bad).is_err(), "{field}");
    }
    let mut missing = plan.clone();
    missing[0]["Plan"]["Plans"][1]["Plans"][0]["Plans"][0]["Plans"][0]["Plans"][1]
        .as_object_mut()
        .unwrap()
        .remove("Actual Rows");
    assert!(validate_sparse_history_plan(&missing).is_err());
    let mut excessive = plan.clone();
    let inputs = excessive[0]["Plan"]["Plans"][1]["Plans"][0]["Plans"][0]["Plans"][0]["Plans"]
        .as_array_mut()
        .unwrap();
    inputs.push(inputs[0].clone());
    assert!(validate_sparse_history_plan(&excessive).is_err());
}
