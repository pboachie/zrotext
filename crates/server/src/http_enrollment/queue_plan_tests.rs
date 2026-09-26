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

// With only a few active rows PostgreSQL may use a small bitmap intersection
// and sort. Preserve the sparse-history assertion without prescribing that
// harmless shape; the populated/capped case below requires direct index limits.
pub(super) fn validate_sparse_history_plan(plan: &Value) -> Result<(), &'static str> {
    fn visit(node: &Value, rows: &mut Vec<f64>, indexed: &mut bool) -> Result<(), &'static str> {
        if node["Index Name"] == "messages_device_state" {
            *indexed = true;
        }
        if node["Relation Name"] == "messages" {
            if node["Node Type"] == "Seq Scan" {
                return Err("sparse queue scanned message history");
            }
            if node
                .get("Rows Removed by Filter")
                .is_some_and(|value| value.as_f64() != Some(0.0))
                || node
                    .get("Rows Removed by Index Recheck")
                    .is_some_and(|value| value.as_f64() != Some(0.0))
            {
                return Err("sparse queue filtered unrelated message history");
            }
            rows.push(
                node["Actual Rows"]
                    .as_f64()
                    .ok_or("missing sparse scan count")?,
            );
        }
        if let Some(children) = node.get("Plans") {
            for child in children.as_array().ok_or("invalid sparse plan children")? {
                visit(child, rows, indexed)?;
            }
        }
        Ok(())
    }
    let root = plan
        .get(0)
        .and_then(|value| value.get("Plan"))
        .ok_or("missing sparse root")?;
    let mut rows = Vec::new();
    let mut indexed = false;
    visit(root, &mut rows, &mut indexed)?;
    rows.sort_by(f64::total_cmp);
    if !indexed || rows != [2.0, 3.0] {
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
    scan["Plans"] =
        json!([{"Node Type":"Bitmap Index Scan", "Index Name":"messages_device_state"}]);
    assert_eq!(validate_sparse_history_plan(&plan), Ok(()));
    plan[0]["Plan"]["Plans"][1]["Plans"][0]["Rows Removed by Filter"] = json!(200000);
    assert!(validate_sparse_history_plan(&plan).is_err());
    plan[0]["Plan"]["Plans"][1]["Plans"][0]["Rows Removed by Filter"] = json!(0);
    plan[0]["Plan"]["Plans"][1]["Plans"][0]["Node Type"] = json!("Seq Scan");
    assert!(validate_sparse_history_plan(&plan).is_err());
}
