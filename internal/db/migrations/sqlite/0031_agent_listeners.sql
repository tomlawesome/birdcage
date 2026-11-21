-- Issue #243: the SMB lure and the SNMP listener were missing from the
-- canary's self-test and from the page's listening row, because both come
-- from the fixed profile port list, which names neither 445 nor 161. The
-- agent now reports each listener on every heartbeat.
--
-- Nullable INTEGER (0/1), like agent_opencanary_up (0025). The value is
-- stored as reported on each heartbeat, and a NULL overwrites: NULL means
-- that listener is configured off on the agent (SNMP road off,
-- MOCKINGBIRD_SMB_AUDIT_PATH unset) or the agent predates the field; 0
-- means configured but not answering; 1 means answering. The scheduler
-- adds a self-test target for each non-NULL column, so a lure that dies
-- fails its self-test, and one that is turned off leaves it.
ALTER TABLE agents ADD COLUMN agent_smb_lure_up INTEGER;
ALTER TABLE agents ADD COLUMN agent_snmp_up INTEGER;
