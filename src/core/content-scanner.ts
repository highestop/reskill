/**
 * ContentScanner - Detect malicious patterns in SKILL.md content
 *
 * Features:
 * - Context-aware: skips safe zones (frontmatter, code blocks, quotes, blockquotes)
 * - 6 built-in detection rules across 3 risk levels
 * - Configurable: override levels, disable rules, add custom rules
 * - Pure string operations in scan() — no fs dependency, suitable for server use
 * - scanFile() convenience method for CLI use
 */

import * as fs from 'node:fs';

// ============================================================================
// Types
// ============================================================================

export type RiskLevel = 'high' | 'medium' | 'low';

export interface ScanFinding {
  /** Rule ID that triggered this finding */
  rule: string;
  /** Risk level */
  level: RiskLevel;
  /** Human-readable description */
  message: string;
  /** Line number in the original content (1-based) */
  line?: number;
  /** Content snippet (truncated) */
  snippet?: string;
}

export interface ScanResult {
  /** false if any high-risk finding exists */
  passed: boolean;
  /** All findings across all rules */
  findings: ScanFinding[];
}

export interface ScanRuleMatch {
  /** Line number (1-based) */
  line?: number;
  /** Optional custom snippet (if omitted, scanner generates from original content) */
  snippet?: string;
}

export interface ScanRule {
  /** Unique rule identifier */
  id: string;
  /** Risk level */
  level: RiskLevel;
  /** Description shown when rule triggers */
  message: string;
  /** Whether to skip safe zones (code blocks, quotes, etc.) when scanning */
  skipSafeZones: boolean;
  /** Detection function — receives content string (masked if skipSafeZones) */
  check: (content: string) => ScanRuleMatch[];
}

export interface ScannerOptions {
  /** Override risk levels for specific rules */
  overrides?: Record<string, RiskLevel>;
  /** Disable specific rules by ID */
  disabledRules?: string[];
  /** Add custom detection rules */
  customRules?: ScanRule[];
}

// ============================================================================
// Safe Zone Masking
// ============================================================================

/**
 * Mask safe zones in Markdown content with spaces, preserving line structure.
 *
 * Safe zones (content replaced with spaces):
 * - YAML frontmatter (`---` ... `---` at file start)
 * - Fenced code blocks (``` or ~~~)
 * - Indented code blocks (4 spaces / tab after blank line)
 * - Blockquotes (`> ` prefix)
 * - Inline code (`` `...` ``)
 * - Double-quoted text (`"..."`, min 3 chars between quotes)
 *
 * Line breaks are preserved so line numbers remain correct.
 */
export function maskSafeZones(content: string): string {
  const lines = content.split('\n');
  const result: string[] = [];

  let inFrontmatter = false;
  let inFencedCode = false;
  let fenceChar = '';
  let fenceLength = 0;
  let prevLineBlank = false;
  let prevLineIndentedCode = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // --- YAML Frontmatter (only at file start) ---
    if (i === 0 && line.trim() === '---') {
      inFrontmatter = true;
      result.push(maskLine(line));
      continue;
    }
    if (inFrontmatter) {
      result.push(maskLine(line));
      if (line.trim() === '---') {
        inFrontmatter = false;
      }
      continue;
    }

    // --- Fenced code blocks (``` or ~~~) ---
    const fenceMatch = line.match(/^(`{3,}|~{3,})/);
    if (!inFencedCode && fenceMatch) {
      inFencedCode = true;
      fenceChar = fenceMatch[1][0];
      fenceLength = fenceMatch[1].length;
      result.push(maskLine(line));
      prevLineBlank = false;
      prevLineIndentedCode = false;
      continue;
    }
    if (inFencedCode) {
      result.push(maskLine(line));
      const closeMatch = line.match(/^(`{3,}|~{3,})\s*$/);
      if (
        closeMatch &&
        closeMatch[1][0] === fenceChar &&
        closeMatch[1].length >= fenceLength
      ) {
        inFencedCode = false;
      }
      prevLineBlank = false;
      prevLineIndentedCode = false;
      continue;
    }

    // --- Blockquote ---
    if (/^>\s?/.test(line)) {
      result.push(maskLine(line));
      prevLineBlank = false;
      prevLineIndentedCode = false;
      continue;
    }

    // --- Indented code block (4 spaces or tab, after blank line) ---
    if (/^(?:    |\t)/.test(line) && (prevLineBlank || prevLineIndentedCode)) {
      result.push(maskLine(line));
      prevLineBlank = false;
      prevLineIndentedCode = true;
      continue;
    }

    // --- Normal line: mask inline code and double-quoted text ---
    result.push(maskInline(line));
    prevLineBlank = line.trim() === '';
    prevLineIndentedCode = false;
  }

  return result.join('\n');
}

/** Replace all characters in a line with spaces (preserving length) */
function maskLine(line: string): string {
  return ' '.repeat(line.length);
}

/**
 * Mask inline code (`` `...` ``) and double-quoted text (`"..."`) within a line.
 * Uses regex replacement for efficiency (avoids char-by-char concatenation on long lines).
 * Single quotes are NOT masked to avoid false matches with apostrophes.
 */
function maskInline(line: string): string {
  let result = line;
  // Inline code: `...`
  result = result.replace(/`[^`]+`/g, (m) => ' '.repeat(m.length));
  // Double-quoted text: "..." (min 3 chars between quotes)
  result = result.replace(/"[^"]{3,}"/g, (m) => ' '.repeat(m.length));
  return result;
}

// ============================================================================
// Rule Helpers
// ============================================================================

/** Find lines matching any of the given patterns, return one match per line */
function findLineMatches(
  content: string,
  patterns: RegExp[],
): ScanRuleMatch[] {
  const lines = content.split('\n');
  const matches: ScanRuleMatch[] = [];

  for (let i = 0; i < lines.length; i++) {
    for (const pattern of patterns) {
      if (pattern.test(lines[i])) {
        matches.push({ line: i + 1 });
        break;
      }
    }
  }

  return matches;
}

// ============================================================================
// Default Rules
// ============================================================================

const SNIPPET_MAX_LENGTH = 120;

/** Built-in detection rules */
export const DEFAULT_RULES: readonly ScanRule[] = [
  // Rule 1: Prompt Injection (high)
  {
    id: 'prompt-injection',
    level: 'high',
    message: 'Detected prompt injection attempt',
    skipSafeZones: true,
    check: (content) =>
      findLineMatches(content, [
        /ignore\s+(all\s+)?previous\s+instructions/i,
        /disregard\s+(all\s+)?(prior|previous|above)\s+(instructions|rules|context)/i,
        /you\s+are\s+now\s+/i,
        /from\s+now\s+on[,\s]+you\s+are/i,
        /new\s+system\s+prompt/i,
        /override\s+(your|the)\s+(system|safety|security)\s+(prompt|rules|instructions)/i,
        /forget\s+(?:all\s+)?(?:your\s+)?(?:previous\s+|prior\s+)?(?:instructions|rules|constraints)/i,
        /entering\s+(a\s+)?new\s+(mode|context|session)/i,
      ]),
  },

  // Rule 2: Data Exfiltration (high)
  {
    id: 'data-exfiltration',
    level: 'high',
    message: 'Detected potential data exfiltration command',
    skipSafeZones: true,
    check: (content) => {
      const lines = content.split('\n');
      const matches: ScanRuleMatch[] = [];

      const commandPattern =
        /\b(curl|wget|fetch|http\.post|requests\.post|nc\b|ncat|netcat)\b/i;
      const sensitivePattern =
        /(\$[A-Z_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH)[A-Z_]*|\$ENV\b|\$\{[^}]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[^}]*\})/i;

      for (let i = 0; i < lines.length; i++) {
        if (commandPattern.test(lines[i]) && sensitivePattern.test(lines[i])) {
          matches.push({ line: i + 1 });
        }
      }

      return matches;
    },
  },

  // Rule 3: Content Obfuscation (high) — scans ALL content including safe zones
  {
    id: 'obfuscation',
    level: 'high',
    message: 'Detected content obfuscation',
    skipSafeZones: false,
    check: (content) => {
      const matches: ScanRuleMatch[] = [];
      const lines = content.split('\n');

      // Zero-width characters (suspicious in any context)
      const zeroWidthPattern = /[\u200B\u200C\u200D\uFEFF\u2060\u180E]/;
      for (let i = 0; i < lines.length; i++) {
        if (zeroWidthPattern.test(lines[i])) {
          matches.push({
            line: i + 1,
            snippet: 'Zero-width Unicode characters detected',
          });
        }
      }

      // Long base64-like strings (>200 continuous chars)
      const base64Pattern = /[A-Za-z0-9+/=]{200,}/;
      for (let i = 0; i < lines.length; i++) {
        if (base64Pattern.test(lines[i])) {
          matches.push({
            line: i + 1,
            snippet: 'Suspicious base64-encoded block detected',
          });
        }
      }

      // Large HTML comments (>200 chars of content)
      const commentRegex = /<!--([\s\S]{200,}?)-->/g;
      let match: RegExpExecArray | null;
      // biome-ignore lint/suspicious/noAssignInExpressions: standard regex exec loop
      while ((match = commentRegex.exec(content)) !== null) {
        const lineNum = content.slice(0, match.index).split('\n').length;
        matches.push({
          line: lineNum,
          snippet: `Large HTML comment block (${match[1].length} chars)`,
        });
      }

      return matches;
    },
  },

  // Rule 4: Sensitive File Access (medium)
  {
    id: 'sensitive-file-access',
    level: 'medium',
    message: 'References sensitive file path',
    skipSafeZones: true,
    check: (content) =>
      findLineMatches(content, [
        /~\/\.ssh\b/,
        /~\/\.aws\b/,
        /~\/\.gnupg\b/,
        /~\/\.config\/gcloud\b/,
        /\bid_rsa\b/i,
        /\bid_ed25519\b/i,
        /\/etc\/passwd\b/,
        /\/etc\/shadow\b/,
        /\.env\b(?!\.\w)/,
      ]),
  },

  // Rule 5: Stealth Instructions (medium) — phrase + action verb matching
  {
    id: 'stealth-instructions',
    level: 'medium',
    message: 'Detected instruction to hide actions from user',
    skipSafeZones: true,
    check: (content) => {
      const actionVerbs =
        'execute|delete|remove|send|transmit|modify|overwrite|install|download|upload|run|write|create|destroy|drop';

      const patterns = [
        new RegExp(`silently\\s+(?:${actionVerbs})`, 'i'),
        new RegExp(
          `without\\s+telling\\s+the\\s+user.{0,30}(?:${actionVerbs})`,
          'i',
        ),
        new RegExp(
          `(?:do\\s+not|don'?t)\\s+show\\s+.{0,40}(?:to\\s+the\\s+user|to\\s+user)`,
          'i',
        ),
        new RegExp(
          `hide\\s+(?:this|the|these|all)\\s+.{0,30}(?:from\\s+the\\s+user|from\\s+user)`,
          'i',
        ),
        new RegExp(
          `(?:do\\s+not|don'?t)\\s+mention\\s+.{0,30}(?:to\\s+the\\s+user|to\\s+user)`,
          'i',
        ),
        new RegExp(
          `keep\\s+(?:this|it)\\s+(?:a\\s+)?secret\\s+from\\s+(?:the\\s+)?user`,
          'i',
        ),
      ];

      // Safe patterns to exclude (common in legitimate DevOps/automation skills)
      const safePatterns = [
        /silently\s+(?:ignore|skip|fail|discard|suppress|continue|pass|drop|swallow)/i,
      ];

      const lines = content.split('\n');
      const matches: ScanRuleMatch[] = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (safePatterns.some((p) => p.test(line))) continue;
        for (const pattern of patterns) {
          if (pattern.test(line)) {
            matches.push({ line: i + 1 });
            break;
          }
        }
      }

      return matches;
    },
  },

  // Rule 6: Oversized Content (low) — scans ALL content
  {
    id: 'oversized-content',
    level: 'low',
    message: 'Content exceeds recommended size limit',
    skipSafeZones: false,
    check: (content) => {
      const MAX_SIZE_BYTES = 50 * 1024;
      const sizeBytes = Buffer.byteLength(content, 'utf-8');
      if (sizeBytes > MAX_SIZE_BYTES) {
        return [
          {
            snippet: `Content size: ${(sizeBytes / 1024).toFixed(1)}KB (limit: 50KB)`,
          },
        ];
      }
      return [];
    },
  },
];

// ============================================================================
// ContentScanner
// ============================================================================

/** Build the effective rule set from defaults + options */
function buildRuleSet(options?: ScannerOptions): ScanRule[] {
  let rules: ScanRule[] = DEFAULT_RULES.map((r) => ({ ...r }));

  if (options?.disabledRules?.length) {
    const disabled = new Set(options.disabledRules);
    rules = rules.filter((r) => !disabled.has(r.id));
  }

  if (options?.overrides) {
    for (const rule of rules) {
      const override = options.overrides[rule.id];
      if (override) {
        rule.level = override;
      }
    }
  }

  if (options?.customRules?.length) {
    rules.push(...options.customRules);
  }

  return rules;
}

/**
 * Content scanner for SKILL.md files.
 *
 * Detects prompt injection, data exfiltration, obfuscation, sensitive file
 * access, stealth instructions, and oversized content.
 *
 * @example
 * ```typescript
 * // Default usage (CLI)
 * const scanner = new ContentScanner();
 * const result = scanner.scan(content);
 *
 * // Custom usage (private registry server)
 * const scanner = new ContentScanner({
 *   overrides: { 'prompt-injection': 'medium' },
 *   disabledRules: ['stealth-instructions'],
 * });
 * ```
 */
export class ContentScanner {
  private rules: ScanRule[];

  constructor(options?: ScannerOptions) {
    this.rules = buildRuleSet(options);
  }

  /**
   * Scan content string for malicious patterns.
   * Pure string operation — no file system access.
   */
  scan(content: string): ScanResult {
    const originalLines = content.split('\n');
    const maskedContent = maskSafeZones(content);

    const findings: ScanFinding[] = [];

    for (const rule of this.rules) {
      const targetContent = rule.skipSafeZones ? maskedContent : content;
      const matches = rule.check(targetContent);

      for (const match of matches) {
        // Use custom snippet if provided, otherwise generate from original content
        const snippet =
          match.snippet ??
          (match.line != null
            ? originalLines[match.line - 1]?.trim().slice(0, SNIPPET_MAX_LENGTH)
            : undefined);

        findings.push({
          rule: rule.id,
          level: rule.level,
          message: rule.message,
          line: match.line,
          snippet,
        });
      }
    }

    const hasHighRisk = findings.some((f) => f.level === 'high');

    return {
      passed: !hasHighRisk,
      findings,
    };
  }

  /**
   * Scan a file for malicious patterns.
   * Convenience wrapper that reads the file then calls scan().
   */
  scanFile(filePath: string): ScanResult {
    const content = fs.readFileSync(filePath, 'utf-8');
    return this.scan(content);
  }
}

// ============================================================================
// ContentScanError
// ============================================================================

/**
 * Error thrown when content scanning detects high-risk findings.
 * Carries the full findings array for display purposes.
 */
export class ContentScanError extends Error {
  readonly findings: ScanFinding[];

  constructor(findings: ScanFinding[]) {
    const highCount = findings.filter((f) => f.level === 'high').length;
    super(
      `Content security scan failed: ${highCount} high-risk finding(s) detected`,
    );
    this.name = 'ContentScanError';
    this.findings = findings;
  }
}
