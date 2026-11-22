#!/usr/bin/env node
import dns from "node:dns/promises";
import fs from "node:fs";

const COMMON_DKIM_SELECTORS = ["google", "selector1", "selector2", "s1", "s2", "k1", "resend", "mailgun", "smtp", "default", "dkim", "postmark"];

async function txtRecords(name) {
  try {
    const rows = await dns.resolveTxt(name);
    return rows.map((r) => r.join(""));
  } catch {
    return [];
  }
}

async function countSpfLookups(domain, seen = new Set(), depth = 0) {
  if (depth > 6 || seen.has(domain.toLowerCase())) return { count: 0, record: null };
  seen.add(domain.toLowerCase());
  const txts = await txtRecords(domain);
  const spf = txts.find((t) => /^v=spf1\b/i.test(t));
  if (!spf) return { count: 0, record: null };

  let lookups = 0;
  const tokens = spf.split(/\s+/).slice(1);
  for (const tok of tokens) {
    const clean = tok.replace(/^[+~?-]/, "");
    if (/^(?:include|redirect)[=:]/i.test(clean)) {
      lookups += 1;
      const sub = clean.split(/[=:]/)[1];
      if (sub && !sub.includes("%{")) {
        const child = await countSpfLookups(sub, seen, depth + 1);
        lookups += child.count;
      }
    } else if (/^(?:a|mx|ptr|exists)(?:[:/]|$)/i.test(clean)) {
      lookups += 1;
    }
  }
  return { count: lookups, record: spf };
}

async function main() {
  const args = process.argv.slice(2);
  let domain = "";
  let minScore = 70;
  let reqDmarc = false;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--min-score") minScore = Number(args[++i] || 70);
    else if (args[i] === "--require-dmarc") reqDmarc = String(args[++i]) === "true";
    else if (!args[i].startsWith("-")) domain = args[i];
  }

  domain = domain.replace(/^https?:\/\//i, "").split("/")[0].replace(/^www\./i, "").trim().toLowerCase();
  if (!domain) {
    console.error("Usage: node src/audit.mjs <domain.com> [--min-score 70]");
    process.exit(2);
  }

  let score = 0;
  const issues = [];

  // 1. MX
  let mxCount = 0;
  try {
    const mx = await dns.resolveMx(domain);
    mxCount = mx.length;
  } catch {}
  if (mxCount > 0) score += 20;
  else issues.push("No MX records found");

  // 2. SPF & Recursive Lookups
  const spfInfo = await countSpfLookups(domain);
  if (spfInfo.record) {
    if (spfInfo.count <= 10) {
      score += 25;
    } else {
      score += 10;
      issues.push(`SPF exceeds RFC 7208 10-lookup limit (${spfInfo.count}/10 -> PermError)`);
    }
    if (/\+all\b/i.test(spfInfo.record)) {
      score -= 20;
      issues.push("Dangerous SPF +all allows universal spoofing");
    }
  } else {
    issues.push("Missing v=spf1 TXT record");
  }

  // 3. DKIM discovery across common selectors
  const dkimChecks = await Promise.all(
    COMMON_DKIM_SELECTORS.map(async (sel) => {
      const txts = await txtRecords(`${sel}._domainkey.${domain}`);
      return txts.some((t) => /v=DKIM1|p=[A-Za-z0-9+/]{32,}/i.test(t)) ? sel : null;
    })
  );
  const activeSelectors = dkimChecks.filter(Boolean);
  if (activeSelectors.length > 0) score += 20;
  else issues.push("No public DKIM selector detected across 12 standard ESP selectors");

  // 4. DMARC
  const dmarcTxts = await txtRecords(`_dmarc.${domain}`);
  const dmarc = dmarcTxts.find((t) => /^v=DMARC1\b/i.test(t)) || "";
  const pMatch = dmarc.match(/\bp=(none|quarantine|reject)\b/i);
  const dmarcPolicy = pMatch ? pMatch[1].toLowerCase() : "missing";
  if (dmarcPolicy === "reject") score += 25;
  else if (dmarcPolicy === "quarantine") score += 20;
  else if (dmarcPolicy === "none") {
    score += 8;
    issues.push("DMARC is in monitoring-only mode (p=none does not block spoofing)");
  } else {
    issues.push("Missing _dmarc TXT record");
  }

  // 5. MTA-STS & BIMI
  const [mtaSts, bimi] = await Promise.all([
    txtRecords(`_mta-sts.${domain}`),
    txtRecords(`default._bimi.${domain}`)
  ]);
  if (mtaSts.some((t) => /v=STSv1/i.test(t))) score += 5;
  if (bimi.some((t) => /v=BIMI1/i.test(t))) score += 5;

  score = Math.max(0, Math.min(100, score));
  const fixUrl = `https://inbox-checker.appwrite.network/?domain=${encodeURIComponent(domain)}&ref=gh-inboxshield-action`;

  console.log(`InboxShield Score for ${domain}: ${score}/100 | MX: ${mxCount} | SPF Lookups: ${spfInfo.count}/10 | DKIM: [${activeSelectors.join(", ") || "none"}] | DMARC: ${dmarcPolicy}`);
  for (const iss of issues) console.log(`  - ${iss}`);
  console.log(`Full 6-Phase DNS Protocol Inspector & Flattened SPF Fix ($2 Launch Special): ${fixUrl}`);

  if (process.env.GITHUB_OUTPUT) {
    fs.appendFileSync(process.env.GITHUB_OUTPUT, `score=${score}\nspf_lookups=${spfInfo.count}\ndmarc_policy=${dmarcPolicy}\n`);
  }

  if (process.env.GITHUB_STEP_SUMMARY) {
    const md = [
      `### InboxShield Email Deliverability Gate: **${score}/100** (${domain})`,
      `- **MX Servers:** ${mxCount} | **SPF Lookups:** ${spfInfo.count}/10 | **DKIM Selectors:** ${activeSelectors.join(", ") || "none"} | **DMARC:** ${dmarcPolicy}`,
      issues.length ? ("\n**Detected Issues:**\n" + issues.map((x) => `- ${x}`).join("\n")) : "\nAll core authentication checks passed.",
      `\nInspect full 6-phase DNS trace & unlock conflict-free flattened SPF + DMARC records (**$2 Launch Special**, ~~$9~~): [${domain} Live Report](${fixUrl})`
    ].join("\n");
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + "\n");
  }

  if (score < minScore || (reqDmarc && !["quarantine", "reject"].includes(dmarcPolicy))) {
    process.exit(1);
  }
}

main();
