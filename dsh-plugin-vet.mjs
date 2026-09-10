#!/usr/bin/env node
/**
 * dsh-plugin-vet — vet a DeepSeek Harness plugin straight from GitHub.
 *
 * Downloads the repository tarball, extracts it to a scratch directory, and
 * reports what the package is made of — WITHOUT installing it into a profile
 * and WITHOUT executing a single line of its code.
 *
 * Two facts make this necessary:
 *
 *   1. A DSH plugin is an ordinary npm package loaded into the harness
 *      process. `apply(ctx, config)` receives a full cordis Context, so it
 *      runs with the harness's own privileges: your credentials file, the
 *      filesystem, the network, child processes. There is no plugin
 *      permission model, no enforced manifest declaration, and no
 *      install-time prompt. The only thing standing between a plugin and your
 *      machine is whether you read it first.
 *
 *   2. What actually lands in node_modules is the package.json `files` field,
 *      not the whole repository. Auditing the wrong set is a real failure mode.
 *
 * Usage:
 *   node dsh-plugin-vet.mjs <owner/repo | github-url> [options]
 *
 * Options:
 *   --ref <ref>   branch, tag, or commit sha (default: the repo's default branch)
 *   --out <dir>   scratch directory (default: under the OS temp dir; falls back to ./.dsh-plugin-vet)
 *   --keep        keep the extracted tree instead of deleting it
 *   --json        machine-readable output
 *   -h, --help
 *
 * Exit codes: 0 = no high-severity findings, 1 = at least one high finding,
 *             2 = the tool itself failed.
 *
 * No dependencies. Node 22+ (global fetch).
 */

import { gunzipSync } from 'node:zlib'
import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join, extname } from 'node:path'
import { tmpdir } from 'node:os'

const API = 'https://api.github.com'
const CODELOAD = 'https://codeload.github.com'
const UA = 'dsh-plugin-vet'
const MAX_SCAN_BYTES = 512 * 1024
const MAX_HITS_PER_RULE = 25

const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.tsx', '.jsx'])
const PATCH_EXT = new Set(['.yml', '.yaml'])

/**
 * Loader rows whose behaviour a plugin can flip through its bundle patch.
 * Overriding these is not automatically malicious — several legitimate plugins
 * do it — but it is always worth a human look, because it changes harness
 * policy rather than adding a feature.
 */
const WATCH_ROWS = new Set([
  'system-prompt', 'tools', 'agent', 'agent-loop', 'session', 'settings',
  'approval', 'user-approval', 'permission', 'permission-presets',
  'sandbox', 'sandbox-policy', 'fs-sandbox', 'fs-observation-policy',
  'credentials', 'llm', 'llm-retry', 'hooks', 'hmr', 'skill', 'subagent',
])

/** @type {{id:string, sev:'high'|'medium'|'low'|'info', re:RegExp, why:string}[]} */
const RULES = [
  {
    id: 'dynamic-code',
    sev: 'high',
    re: /\beval\s*\(|new\s+Function\s*\(|vm\.(?:runIn\w+|compileFunction|createScript)|require\(\s*['"]vm['"]\s*\)/g,
    why: 'executes code built at runtime — static review cannot see the real behaviour',
  },
  {
    id: 'yaml-js-expression',
    sev: 'high',
    re: /!!js\b/g,
    why: 'cordis patch !!js expressions are evaluated when the config loads — config is code',
  },
  {
    id: 'child-process',
    sev: 'high',
    re: /\bchild_process\b|\b(?:execSync|execFileSync|spawnSync|execFile|spawn|fork)\s*\(/g,
    why: 'can start arbitrary processes with your full user rights',
  },
  {
    id: 'credential-path',
    sev: 'high',
    re: /\.credentials|[/\\]\.ssh[/\\]|id_rsa|id_ed25519|[/\\]\.aws[/\\]|\.git-credentials|[/\\]\.npmrc|[/\\]\.netrc|\bLogin Data\b/g,
    why: 'touches a credential or private-key location',
  },
  {
    id: 'destructive-fs',
    sev: 'high',
    re: /\b(?:rmSync|rm|unlinkSync|unlink|rmdirSync|rmdir|chmodSync|chownSync|truncateSync)\s*\(/g,
    why: 'deletes files or changes permissions',
  },
  {
    id: 'network-egress',
    sev: 'medium',
    re: /\bfetch\s*\(|https?\.(?:request|get|post)\s*\(|net\.connect|\bdgram\.|WebSocket\s*\(|require\(\s*['"](?:https?|net|tls)['"]\s*\)/g,
    why: 'can send data out — Node\'s permission model has no network switch, so nothing else blocks this',
  },
  {
    id: 'env-read',
    sev: 'medium',
    re: /process\.env(?:\.[A-Za-z_][A-Za-z0-9_]*|\s*\[)/g,
    why: 'reads environment variables (API keys usually live in env)',
  },
  {
    id: 'obfuscation',
    sev: 'medium',
    re: /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]\s*,\s*['"]base64['"]|\batob\s*\(|(?:\\x[0-9a-fA-F]{2}){8,}/g,
    why: 'base64 / hex-escaped payload — a classic way to hide a string from review',
  },
  {
    id: 'prompt-surface',
    sev: 'info',
    re: /system-prompt|systemPrompt|agent-instructions|persona\b/gi,
    why: 'touches the prompt layer — a transitive power: it can direct the agent to do things',
  },
  {
    id: 'fs-write',
    sev: 'low',
    re: /\b(?:writeFileSync|writeFile|appendFileSync|appendFile|createWriteStream|mkdirSync)\s*\(/g,
    why: 'writes files',
  },
]

const SEV_ORDER = { high: 0, medium: 1, low: 2, info: 3 }
const SEV_LABEL = { high: 'HIGH', medium: 'MED ', low: 'LOW ', info: 'INFO' }

/* ────────────────────────────── tar.gz ────────────────────────────── */

function cstr(buf, off, len) {
  const slice = buf.subarray(off, off + len)
  const end = slice.indexOf(0)
  return (end === -1 ? slice : slice.subarray(0, end)).toString('utf8')
}

/** Minimal tar reader — enough for a GitHub codeload tarball. */
function untar(buf) {
  const out = []
  let off = 0
  let pending = null
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512)
    let blank = true
    for (let i = 0; i < 512; i++) if (h[i] !== 0) { blank = false; break }
    if (blank) break

    const size = parseInt(cstr(h, 124, 12).trim() || '0', 8) || 0
    const flag = String.fromCharCode(h[156] || 48)
    const dataStart = off + 512
    const data = buf.subarray(dataStart, dataStart + size)
    off = dataStart + Math.ceil(size / 512) * 512

    if (flag === 'L') { pending = { type: 'gnu', value: cstr(data, 0, data.length) }; continue }
    if (flag === 'x') { pending = { type: 'pax', value: data.toString('utf8') }; continue }
    if (flag === 'g') continue
    if (flag === '5' || flag === '2') { pending = null; continue }

    let path = cstr(h, 0, 100)
    const prefix = cstr(h, 345, 155)
    if (prefix) path = `${prefix}/${path}`
    if (pending?.type === 'gnu') path = pending.value
    if (pending?.type === 'pax') {
      const m = /^\d+ path=(.*)$/m.exec(pending.value)
      if (m) path = m[1].replace(/\n$/, '')
    }
    pending = null
    if (flag === '0' || flag === '7') out.push({ path, data: Buffer.from(data) })
  }
  return out
}

const sha256 = buf => createHash('sha256').update(buf).digest('hex')

/* ────────────────────────────── GitHub ────────────────────────────── */

function parseSpec(spec) {
  let s = String(spec).trim().replace(/^git\+/, '').replace(/\.git$/, '')
  s = s.replace(/^https?:\/\//, '').replace(/^github\.com\//, '').replace(/^www\./, '')
  let ref = null
  const tree = /\/tree\/(.+)$/.exec(s)
  if (tree) { ref = tree[1]; s = s.slice(0, tree.index) }
  const hash = s.indexOf('#')
  if (hash >= 0) { ref = s.slice(hash + 1); s = s.slice(0, hash) }
  const parts = s.split('/').filter(Boolean)
  if (parts.length < 2) throw new Error(`cannot parse repo spec: ${spec} (want owner/repo or a github.com URL)`)
  return { owner: parts[0], repo: parts[1].replace(/[^\w.-]/g, ''), ref }
}

async function ghJson(path) {
  const res = await fetch(API + path, {
    headers: { 'user-agent': UA, accept: 'application/vnd.github+json' },
  })
  if (res.status === 404) throw new Error(`not found: ${path}`)
  if (!res.ok) throw new Error(`GitHub API ${path} -> ${res.status} ${res.statusText}`)
  return res.json()
}

async function downloadTarball({ owner, repo, ref }) {
  const url = `${CODELOAD}/${owner}/${repo}/tar.gz/${ref}`
  const res = await fetch(url, { headers: { 'user-agent': UA }, redirect: 'follow' })
  if (!res.ok) throw new Error(`tarball download failed: ${res.status} ${res.statusText} (${url})`)
  return { url, buffer: Buffer.from(await res.arrayBuffer()) }
}

/* ────────────────────────────── analysis ────────────────────────────── */

function globToRe(pattern) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&')
  const body = escaped.replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '.*')
  return new RegExp(`^${body}$`)
}

/**
 * Which extracted paths would actually land in node_modules. npm/pnpm always
 * keeps package.json, always drops dotfiles at the root, and expands `files`
 * entries as globs or directory prefixes.
 */
function shippedPaths(paths, filesField) {
  const keep = new Set(['package.json'])
  if (!Array.isArray(filesField) || filesField.length === 0) {
    // No `files` field: essentially the whole repo ships.
    return new Set(paths)
  }
  const patterns = filesField.map(f => String(f).replace(/^\.\//, '').replace(/\/+$/, ''))
  for (const p of paths) {
    for (const pat of patterns) {
      if (globToRe(pat).test(p)) { keep.add(p); break }
      if (!/[*?[\]]/.test(pat) && (p === pat || p.startsWith(`${pat}/`))) { keep.add(p); break }
    }
  }
  return keep
}

function isTextFile(path, data) {
  const ext = extname(path).toLowerCase()
  if (!CODE_EXT.has(ext) && !PATCH_EXT.has(ext) && ext !== '.json' && ext !== '.md' && ext !== '.txt') return false
  if (data.length > MAX_SCAN_BYTES) return false
  return !data.subarray(0, 4096).includes(0)
}

function scanCode(text, relPath) {
  const hits = []
  for (const rule of RULES) {
    const re = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : `${rule.re.flags}g`)
    let m
    let n = 0
    while ((m = re.exec(text)) !== null) {
      if (n++ >= MAX_HITS_PER_RULE) break
      if (m.index === re.lastIndex) re.lastIndex++
      const line = text.slice(0, m.index).split('\n').length
      hits.push({ rule: rule.id, sev: rule.sev, why: rule.why, file: relPath, line, match: m[0].slice(0, 72) })
    }
  }
  return hits
}

/**
 * Textual scan of a cordis patch file. Deliberately not a full YAML parse: a
 * vetting aid should not need a parser to tell you a patch disables the sandbox.
 * Indentation tracking is what separates an inserted child row from a
 * top-level targeted override.
 */
function analyzePatch(text) {
  const targeted = []
  const inserted = []
  const jsExpressions = []
  let insertIndent = -1
  const lines = text.split(/\r?\n/)

  for (let i = 0; i < lines.length; i++) {
    const l = lines[i]
    const indent = (/^(\s*)/.exec(l)?.[1] ?? '').length
    if (indent === 0 && insertIndent !== -1) insertIndent = -1

    if (/!!js/.test(l)) jsExpressions.push({ line: i + 1, text: l.trim() })

    const ins = /^(\s*)(?:-\s*)?insert\s*:/.exec(l)
    if (ins) { insertIndent = ins[1].length; continue }

    const idm = /^(\s*)-\s*id\s*:\s*['"]?([\w@/.-]+)['"]?\s*$/.exec(l)
    if (idm) {
      const entry = { line: i + 1, id: idm[2], disabled: false, name: null }
      if (insertIndent >= 0 && idm[1].length > insertIndent) inserted.push(entry)
      else targeted.push(entry)
      continue
    }

    const nm = /^(\s*)name\s*:\s*['"]?([\w@/.-]+)['"]?\s*$/.exec(l)
    if (nm) {
      const bucket = insertIndent >= 0 && nm[1].length > insertIndent ? inserted : targeted
      if (bucket.length) bucket[bucket.length - 1].name = nm[2]
      continue
    }

    const dm = /^(\s*)disabled\s*:\s*(true|false)\s*$/.exec(l)
    if (dm) {
      const bucket = insertIndent >= 0 && dm[1].length > insertIndent ? inserted : targeted
      if (bucket.length) bucket[bucket.length - 1].disabled = dm[2] === 'true'
    }
  }
  return { targeted, inserted, jsExpressions }
}

/* ────────────────────────────── reporting ────────────────────────────── */

function section(title) { return `\n\x1b[1m${title}\x1b[0m` }

function renderReport(r) {
  const L = []
  L.push(`dsh-plugin-vet — ${r.repo.owner}/${r.repo.repo}`)
  L.push('='.repeat(64))

  L.push(section('repository'))
  const meta = r.meta
  L.push(`  default branch : ${meta.default_branch}`)
  L.push(`  requested ref  : ${r.ref}`)
  L.push(`  commit         : ${r.commit ?? '\x1b[33munresolved — the report may not be reproducible\x1b[0m'}`)
  if (r.commit) L.push(`  pin install at : github:${r.repo.owner}/${r.repo.repo}#${r.commit}`)
  L.push(`  license        : ${meta.license?.spdx_id ?? 'none declared'}`)
  L.push(`  stars          : ${meta.stargazers_count}   forks: ${meta.forks_count}   open issues: ${meta.open_issues_count}`)
  L.push(`  created        : ${meta.created_at}   last push: ${meta.pushed_at}`)
  if (meta.archived) L.push('  \x1b[1mARCHIVED — unmaintained\x1b[0m')
  L.push(`  tarball        : ${r.tarballUrl}`)
  L.push(`  tarball sha256 : ${r.tarballSha}`)
  L.push(`  extracted      : ${r.fileCount} files, ${(r.totalBytes / 1024).toFixed(1)} KiB`)

  L.push(section('package'))
  if (!r.pkg) {
    L.push('  \x1b[33mno package.json at the repository root — this is not an installable package\x1b[0m')
  } else {
    const p = r.pkg
    L.push(`  name/version   : ${p.name ?? '?'} @ ${p.version ?? '?'}`)
    L.push(`  license        : ${p.license ?? 'none declared'}`)
    L.push(`  type           : ${p.type ?? 'commonjs'}`)
    L.push(`  main/exports   : ${p.main ?? '-'} / ${p.exports ? JSON.stringify(p.exports).slice(0, 90) : '-'}`)
    L.push(`  engines        : ${p.engines ? JSON.stringify(p.engines) : '-'}`)
    L.push(`  dependencies   : ${p.dependencies ? Object.entries(p.dependencies).map(([k, v]) => `${k}@${v}`).join(', ') : 'none'}`)
    if (r.entryMissingApply) L.push('  \x1b[33mdeclared entry does not export `apply` — not a cordis plugin\x1b[0m')

    const scripts = p.scripts ?? {}
    const risky = ['preinstall', 'install', 'postinstall', 'prepare', 'prepack', 'postpack', 'prepublishOnly'].filter(k => scripts[k])
    L.push(`  scripts        : ${Object.keys(scripts).length ? Object.keys(scripts).join(', ') : 'none'}`)
    if (risky.length) {
      L.push(`  \x1b[1m\x1b[31m  ▲ install-time scripts present: ${risky.join(', ')}\x1b[0m`)
      L.push('      pnpm >= 10 blocks dependency build scripts until you allowlist them in')
      L.push('      pnpm-workspace.yaml (allowBuilds). Do not allowlist before reading them:')
      for (const k of risky) L.push(`        ${k}: ${scripts[k]}`)
    } else {
      L.push('  install scripts: none — nothing runs at install time')
    }
  }

  L.push(section('DSH bundle wiring'))
  if (!r.dshBundlePatch) {
    L.push('  no `dsh.bundle.patch` declaration.')
    L.push('  Consequence: this package is installed as a plain dependency and never joins the')
    L.push('  profile layer stack. DSH warns about exactly this. It only matters if something')
    L.push('  imports it directly.')
  } else {
    L.push(`  dsh.bundle.patch: ${r.dshBundlePatch}`)
    const patch = r.patch
    if (!patch) {
      L.push(`  \x1b[1m\x1b[31m  ▲ declared patch file is missing from the package\x1b[0m`)
    } else {
      L.push('  --- targeted overrides (patches an existing loader row) ---')
      if (patch.targeted.length === 0) L.push('      none')
      for (const t of patch.targeted) {
        const watch = WATCH_ROWS.has(t.id)
        L.push(`      ${watch ? '\x1b[1m\x1b[31m▲\x1b[0m' : ' '} line ${t.line}: id=${t.id}${t.disabled ? ' \x1b[1m(disabled: true)\x1b[0m' : ''}${watch ? '   <- harness policy row' : ''}`)
      }
      L.push('  --- inserted rows (new plugins mounted into the tree) ---')
      if (patch.inserted.length === 0) L.push('      none')
      for (const t of patch.inserted) {
        const watch = t.name && WATCH_ROWS.has(t.name)
        L.push(`      ${watch ? '\x1b[1m\x1b[31m▲\x1b[0m' : ' '} line ${t.line}: id=${t.id}${t.name ? ` name=${t.name}` : ''}${watch ? '   <- harness policy row' : ''}`)
      }
      if (patch.jsExpressions.length) {
        L.push('  --- !!js expressions (evaluated at config load) ---')
        for (const j of patch.jsExpressions) L.push(`      \x1b[1m\x1b[31m▲\x1b[0m line ${j.line}: ${j.text.slice(0, 100)}`)
      }
      L.push('  (textual scan, not a YAML parse — read the file itself before trusting it)')
    }
  }

  L.push(section('what actually gets installed'))
  L.push(`  ${r.shipped.length} of ${r.fileCount} extracted files ship (package.json \`files\` field)`)
  for (const f of r.shipped.slice(0, 40)) {
    const mark = CODE_EXT.has(extname(f.path).toLowerCase()) ? ' ' : '·'
    L.push(`   ${mark} ${f.path}  ${String(f.size).padStart(7)} B  ${f.sha.slice(0, 16)}`)
  }
  if (r.shipped.length > 40) L.push(`   ... and ${r.shipped.length - 40} more`)
  if (r.shippedNotInFiles?.length) {
    L.push(`  \x1b[33m  note: ${r.shippedNotInFiles.length} scanned file(s) outside the \`files\` list still carry findings\x1b[0m`)
  }

  L.push(section('pattern scan'))
  if (r.hits.length === 0) {
    L.push('  no matches — note this is a heuristic pass, not a clean bill of health')
  } else {
    const bySev = ['high', 'medium', 'low', 'info']
    for (const sev of bySev) {
      const group = r.hits.filter(h => h.sev === sev)
      if (!group.length) continue
      L.push(`  ${SEV_LABEL[sev]}  ${group.length} hit(s)`)
      for (const h of group.slice(0, 30)) {
        L.push(`        ${h.rule}  ${h.file}:${h.line}  ${h.match}`)
      }
      if (group.length > 30) L.push(`        ... ${group.length - 30} more`)
      L.push(`        why: ${group[0].why}`)
    }
  }

  if (r.envKeys.length) {
    L.push(section('environment variables read'))
    L.push(`  ${r.envKeys.join(', ')}`)
  }

  L.push(section('verdict'))
  const counts = { high: 0, medium: 0, low: 0, info: 0 }
  for (const h of r.hits) counts[h.sev]++
  L.push(`  patterns: ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info`)
  for (const f of r.policyFindings) L.push(`  \x1b[1m\x1b[31m▲ ${f}\x1b[0m`)
  for (const n of r.notes ?? []) L.push(`  \x1b[33m• ${n}\x1b[0m`)
  if (counts.high === 0 && r.policyFindings.length === 0) {
    L.push('  No high-severity signal. That is not approval — it means nothing in this')
    L.push('  heuristic pass fired. The plugin still runs with your full privileges. Read')
    L.push('  the entry file before installing; for anything source-visible it is minutes.')
  } else {
    L.push('  High-severity signal present. Read the flagged lines and the patch file')
    L.push('  before installing. Prefer a throwaway profile first:')
    L.push('    dsh plugin --profile scratch add <spec>')
    L.push('    dsh --profile scratch --dump-config')
  }
  L.push('')
  return L.join('\n')
}

/* ────────────────────────────── main ────────────────────────────── */

function usage() {
  const lines = [
    'Usage: node dsh-plugin-vet.mjs <owner/repo | github-url> [options]',
    '',
    'Options:',
    '  --ref <ref>   branch, tag, or commit sha (default: the repo default branch)',
    '  --out <dir>   scratch directory (default: OS temp dir, falls back to ./.dsh-plugin-vet)',
    '  --keep        keep the extracted tree',
    '  --json        machine-readable output',
    '  -h, --help',
    '',
    'Examples:',
    '  node dsh-plugin-vet.mjs icyaaaww/dsh-tool-failure-circuit-breaker',
    '  node dsh-plugin-vet.mjs https://github.com/owner/repo --ref v1.2.0',
  ]
  console.log(lines.join('\n'))
}

function pickScratchDir(name) {
  const candidates = [
    join(tmpdir(), 'dsh-plugin-vet', name),
    join(process.cwd(), '.dsh-plugin-vet', name),
  ]
  const errors = []
  for (const dir of candidates) {
    try { mkdirSync(dir, { recursive: true }); return dir } catch (e) {
      errors.push(`${dir}: ${e.code ?? e.message}`)
    }
  }
  throw new Error(`no writable scratch directory:\n  ${errors.join('\n  ')}`)
}

async function main() {
  const argv = process.argv.slice(2)
  const opts = { spec: null, ref: null, out: null, keep: false, json: false }

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--keep') opts.keep = true
    else if (a === '--json') opts.json = true
    else if (a === '--ref') opts.ref = argv[++i]
    else if (a === '--out') opts.out = argv[++i]
    else if (a === '-h' || a === '--help') { usage(); return 0 }
    else if (a.startsWith('--')) throw new Error(`unknown option: ${a}`)
    else if (!opts.spec) opts.spec = a
    else throw new Error(`unexpected argument: ${a}`)
  }

  if (!opts.spec) { usage(); return 2 }

  const repoRef = parseSpec(opts.spec)
  const meta = await ghJson(`/repos/${repoRef.owner}/${repoRef.repo}`)
  const ref = opts.ref ?? repoRef.ref ?? meta.default_branch

  // Resolve to an immutable commit: a branch name is not a pin, and a vetting
  // report that cannot be reproduced later is worth much less.
  let commit = null
  if (/^[0-9a-f]{40}$/.test(ref)) {
    commit = ref
  } else {
    try {
      commit = (await ghJson(`/repos/${repoRef.owner}/${repoRef.repo}/commits/${encodeURIComponent(ref)}`)).sha
    } catch { /* fall back to the symbolic ref */ }
  }

  const { url: tarballUrl, buffer } = await downloadTarball({ ...repoRef, ref: commit ?? ref })
  const tarballSha = sha256(buffer)

  const entries = untar(gunzipSync(buffer))
  if (entries.length === 0) throw new Error('tarball contained no files')

  // Strip the single wrapping directory codeload adds: owner-repo-sha/
  const roots = new Set(entries.map(e => e.path.split('/')[0]))
  const wrap = roots.size === 1 ? `${[...roots][0]}/` : ''
  const files = entries.map(e => ({
    path: e.path.startsWith(wrap) ? e.path.slice(wrap.length) : e.path,
    data: e.data,
  }))

  const scratch = opts.out ?? pickScratchDir(`${repoRef.owner}-${repoRef.repo}`)
  try {
    for (const f of files) {
      const target = join(scratch, f.path)
      mkdirSync(join(target, '..'), { recursive: true })
      writeFileSync(target, f.data)
    }

    const rootPkg = files.find(f => f.path === 'package.json')
    let pkg = null
    if (rootPkg) { try { pkg = JSON.parse(rootPkg.data.toString('utf8')) } catch { pkg = null } }

    const patchRel = pkg?.dsh?.bundle?.patch ?? null
    const patchFile = patchRel
      ? files.find(f => f.path === String(patchRel).replace(/^\.\//, ''))
      : null

    const shippedSet = shippedPaths(files.map(f => f.path), pkg?.files)

    const hits = []
    const envKeys = new Set()
    for (const f of files) {
      if (!isTextFile(f.path, f.data)) continue
      const text = f.data.toString('utf8')
      const fileHits = scanCode(text, f.path)
      // Findings in files that never ship are informational only.
      const ships = shippedSet.has(f.path)
      for (const h of fileHits) hits.push({ ...h, ships })
      if (CODE_EXT.has(extname(f.path).toLowerCase())) {
        for (const m of text.matchAll(/process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g)) envKeys.add(m[1])
      }
    }

    const policyFindings = []
    let patch = null
    if (patchFile) {
      patch = analyzePatch(patchFile.data.toString('utf8'))
      for (const t of patch.targeted) {
        if (!WATCH_ROWS.has(t.id)) continue
        policyFindings.push(t.disabled
          ? `patch disables harness row \`${t.id}\` (line ${t.line})`
          : `patch overrides harness row \`${t.id}\` (line ${t.line})`)
      }
      for (const t of patch.inserted) {
        if (t.name && WATCH_ROWS.has(t.name)) policyFindings.push(`patch inserts a row named \`${t.name}\` (line ${t.line})`)
      }
      if (patch.jsExpressions.length) {
        policyFindings.push(`${patch.jsExpressions.length} !!js expression(s) evaluated at config load`)
      }
    }

    let entryMissingApply = false
    const mainRel = pkg?.main ?? (pkg?.exports?.['.'] ?? null)
    if (typeof mainRel === 'string') {
      const entry = files.find(f => f.path === String(mainRel).replace(/^\.\//, ''))
      if (entry) {
        const src = entry.data.toString('utf8')
        entryMissingApply = !/export\s+(?:async\s+)?(?:function|const|let|var)\s+apply\b|module\.exports\s*=\s*\{[^}]*\bapply\b/.test(src)
      }
    }

    const shipped = files
      .filter(f => shippedSet.has(f.path))
      .map(f => ({ path: f.path, size: f.data.length, sha: sha256(f.data) }))
      .sort((a, b) => a.path.localeCompare(b.path))

    const shippedNotInFiles = hits.filter(h => !h.ships).map(h => h.file)

    // A prompt-layer hit in shipped *code* (not a doc) is not a vulnerability,
    // but it is a different kind of power than a tool plugin has: it can
    // direct the agent rather than merely run something itself.
    const notes = []
    if (hits.some(h => h.ships && h.rule === 'prompt-surface' && CODE_EXT.has(extname(h.file).toLowerCase()))) {
      notes.push('modifies the system prompt: transitive power — it can direct the agent, not only run code itself')
    }
    if (pkg && !Array.isArray(pkg.files)) {
      notes.push('no `files` field: roughly the whole repository ships, including anything not meant for release')
    }

    const result = {
      repo: { owner: repoRef.owner, repo: repoRef.repo },
      meta, ref, commit, tarballUrl, tarballSha,
      fileCount: files.length,
      totalBytes: files.reduce((n, f) => n + f.data.length, 0),
      pkg,
      dshBundlePatch: patchRel,
      patch,
      entryMissingApply,
      shipped,
      shippedNotInFiles: [...new Set(shippedNotInFiles)],
      notes,
      hits: hits
        .filter(h => h.ships)
        .sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev] || a.file.localeCompare(b.file) || a.line - b.line),
      envKeys: [...envKeys].sort(),
      policyFindings,
      scratch,
    }

    if (opts.json) {
      console.log(JSON.stringify(result, null, 2))
    } else {
      console.log(renderReport(result))
      console.log(`  extracted tree: ${scratch}${opts.keep ? '' : '  (deleted; pass --keep to inspect it)'}`)
    }

    const high = result.hits.filter(h => h.sev === 'high').length + policyFindings.length
    return high > 0 ? 1 : 0
  } finally {
    if (!opts.keep && !opts.out) {
      try { rmSync(scratch, { recursive: true, force: true }) } catch { /* best effort */ }
    }
  }
}

let exitCode = 0
try {
  exitCode = await main()
} catch (err) {
  console.error(`dsh-plugin-vet: ${err.message}`)
  exitCode = 2
}
process.exitCode = exitCode

// Undici keeps pooled sockets alive after the last response. Closing the
// global dispatcher lets the process end on its own; calling process.exit()
// here instead would race stdout's flush and trip a libuv assertion on Windows.
try {
  const dispatcher = globalThis[Symbol.for('undici.globalDispatcher.1')]
  if (dispatcher && typeof dispatcher.close === 'function') await dispatcher.close()
} catch { /* not fatal — the process still ends on the idle timeout */ }
