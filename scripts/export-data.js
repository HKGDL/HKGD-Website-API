#!/usr/bin/env node
/**
 * Export data from existing SQLite database to SQL seed file for D1
 * Run this script from the worker directory: node scripts/export-data.js
 */

import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Path to the original database
const DB_PATH = path.resolve(__dirname, '../../api/hkgd.db');
const OUTPUT_PATH = path.resolve(__dirname, '../seed.sql');

console.log('Exporting data from:', DB_PATH);

try {
  const db = new Database(DB_PATH, { readonly: true });
  
  const tables = ['levels', 'records', 'changelog', 'members', 'pending_submissions', 'website_content'];
  const statements = [];
  
  for (const table of tables) {
    try {
      const rows = db.prepare(`SELECT * FROM ${table}`).all();
      
      if (rows.length > 0) {
        statements.push(`\n-- Data for ${table} (${rows.length} rows)`);
        
        for (const row of rows) {
          const columns = Object.keys(row);
          const values = Object.values(row).map(v => {
            if (v === null) return 'NULL';
            if (typeof v === 'number') return v;
            // Escape single quotes and wrap in quotes
            return `'${String(v).replace(/'/g, "''")}'`;
          });
          
          statements.push(
            `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${values.join(', ')});`
          );
        }
      } else {
        statements.push(`\n-- No data in ${table}`);
      }
    } catch (err) {
      console.log(`Table ${table} not found or empty, skipping...`);
    }
  }
  
  db.close();
  
  // Write to seed file
  const content = `-- HKGD Database Seed Data\n-- Generated: ${new Date().toISOString()}\n${statements.join('\n')}\n`;
  fs.writeFileSync(OUTPUT_PATH, content);
  
  console.log(`\nExport complete! Output: ${OUTPUT_PATH}`);
  console.log(`Total statements: ${statements.filter(s => s.startsWith('INSERT')).length}`);
  
} catch (error) {
  console.error('Error exporting data:', error);
  process.exit(1);
}