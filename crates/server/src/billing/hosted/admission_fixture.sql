-- SPDX-License-Identifier: AGPL-3.0-only
-- Isolated adapter contract. Not an assigned production migration or a seed.
ALTER TABLE hosted_billing_namespaces ADD CONSTRAINT hosted_namespace_mode_identity UNIQUE(namespace_id,mode);
ALTER TABLE hosted_billing_projections ADD CONSTRAINT hosted_projection_scope_identity
    UNIQUE(namespace_id,account_id,customer_id,subscription_id);
CREATE TABLE hosted_billing_ledger_bindings (
    account_id uuid PRIMARY KEY,
    namespace_id uuid NOT NULL,
    customer_id text NOT NULL CHECK(customer_id ~ '^[A-Za-z0-9_]{1,128}$'),
    subscription_id text NOT NULL CHECK(subscription_id ~ '^[A-Za-z0-9_]{1,128}$'),
    ledger_mode text NOT NULL CHECK(ledger_mode='test'),
    FOREIGN KEY(namespace_id,ledger_mode) REFERENCES hosted_billing_namespaces(namespace_id,mode),
    FOREIGN KEY(namespace_id,account_id,customer_id,subscription_id)
        REFERENCES hosted_billing_projections(namespace_id,account_id,customer_id,subscription_id),
    FOREIGN KEY(account_id,customer_id) REFERENCES billing_customers(account_id,stripe_customer_id),
    FOREIGN KEY(account_id,subscription_id) REFERENCES billing_reconciliations(account_id,stripe_subscription_id)
);
CREATE FUNCTION hosted_ledger_binding_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'hosted ledger binding is immutable' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER hosted_ledger_binding_immutable BEFORE UPDATE ON hosted_billing_ledger_bindings
FOR EACH ROW EXECUTE FUNCTION hosted_ledger_binding_immutable();
