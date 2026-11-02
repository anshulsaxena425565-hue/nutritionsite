-- Additional contact fields for the existing dietitian profile schema.
-- business_name, practice_location, headline, session_minutes and
-- profile_photo_data_url are already present in the base schema.
ALTER TABLE dietitian_profiles ADD COLUMN contact_email TEXT NOT NULL DEFAULT '';
ALTER TABLE dietitian_profiles ADD COLUMN contact_phone TEXT NOT NULL DEFAULT '';
ALTER TABLE dietitian_profiles ADD COLUMN website TEXT NOT NULL DEFAULT '';
