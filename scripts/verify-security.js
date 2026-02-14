#!/usr/bin/env node
/**
 * BlindKey/OpenClaw Security Verification Script
 * Run this to verify your installation meets security requirements
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

const checks = [];
let passed = 0;
let failed = 0;
let warnings = 0;

function check(name, condition, severity = 'error') {
  if (condition) {
    console.log(`${GREEN}✓${RESET} ${name}`);
    passed++;
  } else if (severity === 'warn') {
    console.log(`${YELLOW}⚠${RESET} ${name}`);
    warnings++;
  } else {
    console.log(`${RED}✗${RESET} ${name}`);
    failed++;
  }
}

console.log('\n🔐 BlindKey/OpenClaw Security Verification\n');
console.log('=' .repeat(50) + '\n');

// Check .env file exists
const envPath = path.join(__dirname, '..', '.env');
const envExists = fs.existsSync(envPath);
check('.env file exists', envExists);

if (envExists) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  const envVars = {};
  envContent.split('\n').forEach(line => {
    const match = line.match(/^([A-Z_]+)=(.*)$/);
    if (match) envVars[match[1]] = match[2];
  });

  // Check VAULT_MASTER_KEY
  const masterKey = envVars.VAULT_MASTER_KEY;
  check('VAULT_MASTER_KEY is set', !!masterKey);
  check('VAULT_MASTER_KEY is 64 hex chars (32 bytes)', masterKey && /^[a-f0-9]{64}$/i.test(masterKey));
  check('VAULT_MASTER_KEY is not all zeros', masterKey && !/^0+$/.test(masterKey));

  // Check JWT_SECRET
  const jwtSecret = envVars.JWT_SECRET;
  check('JWT_SECRET is set', !!jwtSecret);
  check('JWT_SECRET is at least 64 chars', jwtSecret && jwtSecret.length >= 64);
  check('JWT_SECRET is not default value', jwtSecret && jwtSecret !== 'change-me-in-production');

  // Check SESSION_SECRET
  const sessionSecret = envVars.SESSION_SECRET;
  check('SESSION_SECRET is set', !!sessionSecret);
  check('SESSION_SECRET is at least 64 chars', sessionSecret && sessionSecret.length >= 64);
  check('SESSION_SECRET is not default value', sessionSecret && sessionSecret !== 'change-me-in-production-too');

  // Check database credentials
  const dbUrl = envVars.DATABASE_URL;
  check('DATABASE_URL is set', !!dbUrl);
  check('DATABASE_URL does not use default password', dbUrl && !dbUrl.includes('agentvault_dev'));

  // Check Redis
  const redisUrl = envVars.REDIS_URL;
  check('REDIS_URL is set', !!redisUrl);
  check('Redis authentication is configured', redisUrl && redisUrl.includes('@'), 'warn');

  // Check NODE_ENV
  check('NODE_ENV is production', envVars.NODE_ENV === 'production', 'warn');
}

// Check .gitignore
const gitignorePath = path.join(__dirname, '..', '.gitignore');
if (fs.existsSync(gitignorePath)) {
  const gitignore = fs.readFileSync(gitignorePath, 'utf8');
  check('.env is in .gitignore', gitignore.includes('.env'));
}

// Check paranoid policy exists
const paranoidPath = path.join(__dirname, '..', 'policies', 'paranoid.yaml');
check('Paranoid policy template exists', fs.existsSync(paranoidPath));

// Check schema.sql exists
const schemaPath = path.join(__dirname, '..', 'schema.sql');
check('Database schema exists', fs.existsSync(schemaPath));

if (fs.existsSync(schemaPath)) {
  const schema = fs.readFileSync(schemaPath, 'utf8');
  check('Audit log has append-only protection', schema.includes('prevent_audit_modification'));
}

// Summary
console.log('\n' + '='.repeat(50));
console.log(`\n${GREEN}Passed:${RESET} ${passed}`);
console.log(`${YELLOW}Warnings:${RESET} ${warnings}`);
console.log(`${RED}Failed:${RESET} ${failed}`);

if (failed > 0) {
  console.log(`\n${RED}❌ Security verification FAILED${RESET}`);
  console.log('Please fix the issues above before running in production.\n');
  process.exit(1);
} else if (warnings > 0) {
  console.log(`\n${YELLOW}⚠ Security verification passed with warnings${RESET}`);
  console.log('Consider addressing the warnings for maximum security.\n');
  process.exit(0);
} else {
  console.log(`\n${GREEN}✅ Security verification PASSED${RESET}`);
  console.log('Your BlindKey/OpenClaw installation meets security requirements.\n');
  process.exit(0);
}
