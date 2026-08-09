ALTER TABLE platformer_levels ADD COLUMN hkgd_plat_rank INTEGER;
UPDATE platformer_levels SET hkgd_plat_rank = hkgd_rank WHERE hkgd_plat_rank IS NULL;
