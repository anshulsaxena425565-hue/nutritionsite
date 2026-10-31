-- 0006_subscription_plan_catalogue.sql
-- Dynamic subscription catalogue and dietitian subscription records.
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS subscription_plans (
 id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 price_minor INTEGER NOT NULL DEFAULT 0 CHECK(price_minor>=0), prices_minor_json TEXT NOT NULL DEFAULT '{}',
 patient_limit INTEGER NOT NULL DEFAULT 10 CHECK(patient_limit>0), is_unlimited INTEGER NOT NULL DEFAULT 0 CHECK(is_unlimited IN (0,1)),
 trial_days INTEGER NOT NULL DEFAULT 14 CHECK(trial_days>=0 AND trial_days<=365), features_json TEXT NOT NULL DEFAULT '[]',
 is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)), is_featured INTEGER NOT NULL DEFAULT 0 CHECK(is_featured IN (0,1)),
 sort_order INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 updated_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_subscription_plans_active_sort ON subscription_plans(is_active,sort_order,name);
CREATE TABLE IF NOT EXISTS dietitian_subscriptions (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES app_users(id) ON DELETE CASCADE,
 plan_id TEXT NOT NULL REFERENCES subscription_plans(id) ON DELETE RESTRICT,
 status TEXT NOT NULL DEFAULT 'trialing' CHECK(status IN ('trialing','active','comped','suspended','cancelled','expired')),
 trial_ends_at TEXT, current_period_start TEXT, current_period_end TEXT,
 admin_override INTEGER NOT NULL DEFAULT 0 CHECK(admin_override IN (0,1)), override_reason TEXT,
 created_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 updated_at TEXT NOT NULL DEFAULT(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_dietitian_subscriptions_status ON dietitian_subscriptions(status,current_period_end);
INSERT OR IGNORE INTO subscription_plans
(id,slug,name,description,price_minor,prices_minor_json,patient_limit,is_unlimited,trial_days,features_json,is_active,is_featured,sort_order)
VALUES
('plan-basic','basic','Basic','For dietitians starting their private practice.',9900,'{"monthly":9900,"quarterly":0,"half_yearly":0,"yearly":0}',10,0,14,'["Patient management","Diet planning","Basic progress tracking"]',1,0,1),
('plan-pro','pro','Pro','For growing practices managing more clients.',49900,'{"monthly":49900,"quarterly":0,"half_yearly":0,"yearly":0}',100,0,14,'["Everything in Basic","Advanced diet planning","Patient progress tracking","Consultation management"]',1,1,2),
('plan-advanced','advanced','Advanced','For established practices with high patient volume.',99900,'{"monthly":99900,"quarterly":0,"half_yearly":0,"yearly":0}',1000000,1,14,'["Everything in Pro","Unlimited patients","Priority practice tools"]',1,0,3);
