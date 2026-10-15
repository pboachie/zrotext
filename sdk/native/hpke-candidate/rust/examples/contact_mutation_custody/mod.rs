//! Ordinary installed protected transition consumer; no private fixture signing.
use super::*;

pub fn run(f: &Value, custody: &contact_custody::Session) -> Result<Value, ()> {
    let root = enroll_root(&decode(&f["rootPin"])?, &decode(&f["fingerprint"])?).map_err(|_| ())?;
    let m = verify_manifest(&decode(&f["manifest"])?, &root, None, 2, 10000).map_err(|_| ())?;
    let n =
        verify_manifest(&decode(&f["nextManifest"])?, &root, Some(&m), 2, 10000).map_err(|_| ())?;
    let expected = Expected {
        account: array(&f["account"])?,
        origin: f["origin"].as_str().ok_or(())?.into(),
        root_fingerprint: array(&f["fingerprint"])?,
        contact: array(&f["contact"])?,
        routing_digest: array(&f["routing"])?,
    };
    let statements = [&m, &n]
        .into_iter()
        .zip(["statement", "nextStatement"])
        .map(|(manifest, key)| {
            verify_statement02(
                &decode(&f[key])?,
                manifest,
                &expected.account,
                &expected.origin,
                &expected.root_fingerprint,
            )
            .map_err(|_| ())
        })
        .collect::<Result<Vec<_>, ()>>()?;
    let mut fields = Vec::new();
    for (i, name) in ["name", "notes", "replacement"].into_iter().enumerate() {
        let b = decode(&f[name])?;
        if b.len() < 396 {
            return Err(());
        }
        let input = FieldInput {
            kind: b[5],
            seal_revision: u64::from_be_bytes(b[38..46].try_into().map_err(|_| ())?),
            request_id: b[198..214].try_into().map_err(|_| ())?,
            encapsulation: b[246..311].try_into().map_err(|_| ())?,
            ciphertext: b[315..b.len() - 64].to_vec(),
        };
        fields.push(
            custody
                .produce(
                    &statements[usize::from(i == 2)],
                    &expected,
                    &input,
                    &Cancellation::default(),
                    false,
                )?
                .verified()
                .clone(),
        );
    }
    let slot = |i: usize| Slot {
        tag: 1,
        seal_revision: u64::from_be_bytes(
            fields[i].signed_bytes()[38..46]
                .try_into()
                .expect("verified field"),
        ),
        digest: fields[i].digest(),
    };
    let mut previous: Option<Transition> = None;
    let mut previous_statement = None;
    let mut mutations = serde_json::Map::new();
    for name in ["create", "update", "clear", "converted"] {
        let st = &statements[usize::from(["update", "clear"].contains(&name))];
        let mut input = super::input(&decode(&f[name])?)?;
        let replacements = match name {
            "create" | "converted" => {
                previous = None;
                previous_statement = None;
                input.name = slot(0);
                input.notes = slot(1);
                vec![fields[0].clone(), fields[1].clone()]
            }
            "update" => {
                input.name = slot(0);
                input.notes = slot(2);
                vec![fields[2].clone()]
            }
            _ => {
                input.notes = slot(2);
                vec![]
            }
        };
        if let Some(p) = &previous {
            input.previous_digest = p.mutation().digest();
        }
        let proposal = Proposal {
            statement: st.clone(),
            expected: expected.clone(),
            expected_legacy: input.legacy_generation,
            input,
            previous: previous.clone(),
            previous_statement: previous_statement.clone(),
            replacements,
        };
        let result = custody.produce_mutation(&proposal, &Cancellation::default(), false)?;
        if custody
            .produce_mutation(&proposal, &Cancellation::default(), true)
            .is_ok()
        {
            return Err(());
        }
        let cancelled = Cancellation::default();
        cancelled.cancel();
        if custody
            .produce_mutation(&proposal, &cancelled, false)
            .is_ok()
        {
            return Err(());
        }
        let mut wrong = proposal.clone();
        wrong.expected.routing_digest = [0; 32];
        if custody
            .produce_mutation(&wrong, &Cancellation::default(), false)
            .is_ok()
        {
            return Err(());
        }
        mutations.insert(name.into(), json!(STANDARD.encode(result.signed_bytes())));
        previous = Some(result.verified().clone());
        previous_statement = Some(st.clone());
    }
    let encoded: serde_json::Map<String, Value> = ["name", "notes", "replacement"]
        .into_iter()
        .zip(&fields)
        .map(|(name, field)| (name.into(), json!(STANDARD.encode(field.signed_bytes()))))
        .collect();
    Ok(json!({"fields":encoded,"mutations":mutations,"refusals":12}))
}
