-- SPDX-License-Identifier: AGPL-3.0-only
-- Optional metadata v2: Android-reported service state, never dispatch authority.
-- Existing v1 reports remain NULL and explicitly clear a previous v2 observation.
ALTER TABLE device_preconditions ADD COLUMN network_service text
    CHECK (network_service IN ('in_service','out_of_service','emergency_only','power_off','unavailable'));
