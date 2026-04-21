# HKGD API Changelog

## Version 0.8.0

### New Endpoints
- **`POST /api/levels/sync-details`** - Sync level details (creator, thumbnail, songs) from History GD API for rated levels (limited to 50 levels per sync)
- **`POST /api/platformer-levels/sync-details`** - Sync platformer level details from History GD API
- **`GET /api/gdbrowser/level/:levelId`** - Fetch level details from History GD API with fallback to GDBrowser
- **`GET /api/gdbrowser/search`** - Search levels using History GD API with platformer filter
- **`GET /api`** - Root endpoint returning API info and available endpoints

### Platformer System
- **Separate Platformer Tables** - Created `platformer_levels` and `platformer_records` tables via migration
- **Platformer Submissions** - Added `POST /api/platformer-submissions` for platformer record submissions
- **Admin Difficulty Decider** - Admins can set HKGD difficulty rank when approving platformer submissions

### Improvements
- **History GD Integration** - Use History GD API for level lookups and search (filters for platformer levels with cache_length=5)
- **Better Fields** - Uses `cache_username`, `cache_song_id` from History GD API responses
- **Thumbnail Handling** - Uses levelthumbs.prevter.me for thumbnails
- **Optimized Sync** - Batch sync limited to 50 levels to avoid timeouts

### Other Changes
- Added README with setup instructions
- Added IP ban management endpoints
- Added suggestions system endpoints
- Fixed record creation/update/delete handling

---

## Version 0.5.0 - 0.7.0

*(Previous versions consolidated into 0.8.0)*

---

*For older changes, please check the GitHub commits.*
