ALTER TABLE remediations ADD COLUMN provider_id TEXT REFERENCES ai_providers(id) ON DELETE SET NULL;
