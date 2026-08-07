-- Renumber hkgd_rank to fill any gaps, ordered by AREDL rank.
-- Idempotent: safe to run multiple times. Matches /api/admin/renumber-ranks logic.
UPDATE levels
SET hkgd_rank = (
  SELECT new_rank FROM (
    SELECT id, ROW_NUMBER() OVER (ORDER BY aredl_rank ASC, hkgd_rank ASC) AS new_rank
    FROM levels
    WHERE hidden IS NULL OR hidden != 1
  ) ranked
  WHERE ranked.id = levels.id
);
UPDATE levels SET hkgd_rank = 0 WHERE hidden = 1;
