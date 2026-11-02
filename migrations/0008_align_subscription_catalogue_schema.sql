-- 0008_align_subscription_catalogue_schema.sql
-- Add the dynamic catalogue fields expected by the current billing API to the
-- existing production subscription_plans table. The original table predates
-- the dynamic catalogue, so CREATE TABLE IF NOT EXISTS in migration 0006 did
-- not add these columns.
ALTER TABLE subscription_plans ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE subscription_plans ADD COLUMN prices_minor_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE subscription_plans ADD COLUMN trial_days INTEGER NOT NULL DEFAULT 14;
ALTER TABLE subscription_plans ADD COLUMN is_featured INTEGER NOT NULL DEFAULT 0;

UPDATE subscription_plans
SET
  description = CASE slug
    WHEN 'basic' THEN 'For dietitians starting their private practice.'
    WHEN 'pro' THEN 'For growing practices managing more clients.'
    WHEN 'advance' THEN 'For established practices with unlimited patient capacity.'
    ELSE description
  END,
  prices_minor_json = json_object(
    'monthly', price_minor,
    'quarterly', 0,
    'half_yearly', 0,
    'yearly', 0
  ),
  trial_days = 14,
  is_featured = CASE WHEN slug = 'pro' THEN 1 ELSE 0 END;
