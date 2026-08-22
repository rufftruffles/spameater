#!/usr/bin/env node
'use strict';

// Seeds a sample inbox JSON into $SPAMEATER_HOME/data/inboxes for local
// development and screenshots. Mirrors the shape written by
// haraka/plugins/save_email.js updateInboxJSON().
//
// Usage: SPAMEATER_HOME=$PWD/.devhome node scripts/seed-inbox.js

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const HOME = process.env.SPAMEATER_HOME || path.join(process.cwd(), '.devhome');
const INBOX_DIR = path.join(HOME, 'data', 'inboxes');
const PREFIX = process.env.SEED_PREFIX || 'midnight-fox42';
const DOMAIN = process.env.EMAIL_DOMAIN || 'spameater.io';

const lightHtml = fs.readFileSync(path.join(__dirname, '..', 'test', 'fixtures', 'light-marketing.html'), 'utf8');
const darkHtml = fs.readFileSync(path.join(__dirname, '..', 'test', 'fixtures', 'dark-designed.html'), 'utf8');
const plainText = fs.readFileSync(path.join(__dirname, '..', 'test', 'fixtures', 'plain-text.txt'), 'utf8');

const now = Date.now();

function email(minutesAgo, fields) {
    return Object.assign({
        id: crypto.randomUUID(),
        receivedAt: Math.floor((now - minutesAgo * 60 * 1000) / 1000),
        spfResult: 'pass',
        dkimResult: 'pass'
    }, fields);
}

const data = {
    email: `${PREFIX}@${DOMAIN}`,
    count: 4,
    updated: Math.floor(now / 1000),
    expires_at: new Date(now + 22 * 60 * 60 * 1000).toISOString(),
    emails: [
        email(0.2, {
            sender: 'noreply@github.com',
            senderName: 'GitHub',
            subject: '[GitHub] Please verify your device',
            bodyText: 'A sign-in attempt requires further verification.',
            bodyHtml: darkHtml,
            size: 18432,
            messageId: '<verify-device@github.com>'
        }),
        email(4, {
            sender: 'no-reply@figma.com',
            senderName: 'Figma',
            subject: 'Verify your email address',
            bodyText: 'Click the button below to confirm this address.',
            bodyHtml: lightHtml,
            size: 24576,
            messageId: '<verify-email@figma.com>'
        }),
        email(63, {
            sender: 'digest@hndigest.example.org',
            senderName: 'Hacker News Digest',
            subject: 'Top stories this week',
            bodyText: plainText,
            bodyHtml: null,
            size: 4096,
            messageId: '<weekly@hndigest.example.org>',
            dkimResult: 'none'
        }),
        email(190, {
            sender: 'noreply@steampowered.com',
            senderName: 'Steam',
            subject: 'Your Steam account: Access from new device',
            bodyText: 'If this was not you, change your password.',
            bodyHtml: lightHtml,
            size: 20480,
            messageId: '<newdevice@steampowered.com>',
            spfResult: 'softfail'
        })
    ]
};

fs.mkdirSync(INBOX_DIR, { recursive: true });
const out = path.join(INBOX_DIR, `${PREFIX}.json`);
fs.writeFileSync(out, JSON.stringify(data, null, 2));
console.log(`Seeded ${out} (${data.count} emails, expires ${data.expires_at})`);
