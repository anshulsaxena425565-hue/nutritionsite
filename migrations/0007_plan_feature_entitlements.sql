-- 0007_plan_feature_entitlements.sql
-- Separate actual feature permissions from the marketing feature list.
ALTER TABLE subscription_plans ADD COLUMN entitlements_json TEXT NOT NULL DEFAULT '{}';

-- Preserve current access for existing customers during rollout. Superadmin can
-- explicitly switch off individual capabilities per plan afterwards.
UPDATE subscription_plans
SET entitlements_json = '{"patient_management":true,"diet_planning":true,"client_communication":true,"appointments":true,"team_collaboration":true,"advanced_analytics":true,"data_export":true,"advanced_tools":true,"client_feedback":true}'
WHERE entitlements_json = '{}' OR entitlements_json IS NULL;
