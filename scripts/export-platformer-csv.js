#!/usr/bin/env node
/**
 * Export platformer levels and records to CSV format
 * Run this script from the api directory: node scripts/export-platformer-csv.js
 */

import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Path to the database
const DB_PATH = path.resolve(__dirname, '../hkgd.db');
const OUTPUT_PATH = path.resolve(__dirname, '../../HKGD Platformer Demons.csv');

console.log('Exporting platformer data from:', DB_PATH);

try {
  const db = new Database(DB_PATH, { readonly: true });
  
  // Get platformer levels
  const levels = db.prepare(`
    SELECT 
      id, hkgd_rank as hkgdRank, name, creator, verifier, level_id as levelId, 
      description, thumbnail, song_id as songId, song_name as songName, 
      tags, date_added as dateAdded, pack, difficulty
    FROM platformer_levels
    ORDER BY hkgd_rank
  `).all();

  // Get platformer records
  const records = db.prepare(`
    SELECT 
      level_id as levelId, player, date, video_url as videoUrl, 
      fps, cbf, attempts
    FROM platformer_records
    ORDER BY level_id, date
  `).all();

  db.close();

  if (levels.length === 0) {
    console.log('No platformer levels found in database.');
    process.exit(0);
  }

  // Create CSV header
  const header = [
    'HKGD Rank', 'Level ID', 'Name', 'Creator', 'Verifier', 'Date Added',
    'Player 1', 'Date (P1)', 'Video (P1)', 'FPS (P1)', 'CBF (P1)', 'Attempts (P1)',
    'Player 2', 'Date (P2)', 'Video (P2)', 'FPS (P2)', 'CBF (P2)', 'Attempts (P2)',
    'Player 3', 'Date (P3)', 'Video (P3)', 'FPS (P3)', 'CBF (P3)', 'Attempts (P3)',
    'Player 4', 'Date (P4)', 'Video (P4)', 'FPS (P4)', 'CBF (P4)', 'Attempts (P4)',
    'Player 5', 'Date (P5)', 'Video (P5)', 'FPS (P5)', 'CBF (P5)', 'Attempts (P5)'
  ];

  const rows = [];
  rows.push(header.join(','));

  // Group records by level
  const recordsByLevel = {};
  records.forEach(record => {
    if (!recordsByLevel[record.levelId]) {
      recordsByLevel[record.levelId] = [];
    }
    recordsByLevel[record.levelId].push(record);
  });

  // Create CSV rows
  levels.forEach(level => {
    const levelRecords = recordsByLevel[level.id] || [];
    const row = [
      level.hkgdRank || '',
      level.levelId || '',
      `"${level.name}"`,
      `"${level.creator}"`,
      `"${level.verifier || ''}"`,
      level.dateAdded || ''
    ];

    // Add up to 5 records
    for (let i = 0; i < 5; i++) {
      const record = levelRecords[i];
      row.push(record ? `"${record.player}"` : '');
      row.push(record ? record.date : '');
      row.push(record ? record.videoUrl : '');
      row.push(record ? record.fps : '');
      row.push(record ? (record.cbf ? 'Yes' : 'No') : '');
      row.push(record ? record.attempts : '');
    }

    rows.push(row.join(','));
  });

  // Write to CSV file
  const content = rows.join('\n');
  fs.writeFileSync(OUTPUT_PATH, content);
  
  console.log(`\nExport complete! Output: ${OUTPUT_PATH}`);
  console.log(`Exported ${levels.length} platformer levels with ${records.length} total records`);
  
} catch (error) {
  console.error('Error exporting platformer data:', error);
  process.exit(1);
}