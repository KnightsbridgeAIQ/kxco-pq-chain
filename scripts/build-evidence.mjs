// Evidence bundle for a package that consumes the KXCO post-quantum primitives
// rather than implementing them.
//
// The primitives package runs NIST ACVP vectors and a cross-implementation
// interoperability matrix. Nothing here repeats that work, and repeating it
// would be worse than not: a second copy of a conformance claim invites the
// reader to count it twice.
//
// The number that matters most here is the RESOLVED primitives version. This
// package declares a range, and a range is not a configuration. An assessor
// asking which implementation actually ran needs the version that was
// installed, and that is what the manifest carries.
//
// Usage: node scripts/build-evidence.mjs [--out dist/evidence]

import { execFileSync } from 'node:child_process'
import {
  mkdirSync, writeFileSync, copyFileSync, readFileSync, existsSync, rmSync, readdirSync,
} from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const args = process.argv.slice(2)
const outDir = args.includes('--out')
  ? args[args.indexOf('--out') + 1]
  : join(ROOT, 'dist', 'evidence')

const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'))
const steps = []

rmSync(outDir, { recursive: true, force: true })
mkdirSync(outDir, { recursive: true })

function run(name, file, argv, { optional = false } = {}) {
  const started = Date.now()
  try {
    // npm on Windows is a .cmd shim. Node refuses to spawn one directly
    // (EINVAL) and shell:true concatenates arguments without escaping them
    // (DEP0190), so go through cmd.exe explicitly with the arguments still in
    // an array.
    const win = process.platform === 'win32'
    const bin = win ? 'cmd.exe' : file
    const spawnArgs = win ? ['/c', file, ...argv] : argv
    const stdout = execFileSync(bin, spawnArgs, {
      cwd: ROOT,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    })
    steps.push({ name, command: [file, ...argv].join(' '), ok: true, ms: Date.now() - started })
    return stdout
  } catch (err) {
    // A failed step is recorded, never dropped. A bundle that quietly omits
    // what did not pass is not evidence.
    steps.push({
      name,
      command: [file, ...argv].join(' '),
      ok: false,
      ms: Date.now() - started,
      error: (err.stderr || err.message || '').toString().slice(0, 4000),
    })
    if (!optional) throw err
    return null
  }
}

function write(name, contents) {
  writeFileSync(join(outDir, name), contents)
}

// -- 1. identity -------------------------------------------------------------

const git = (argv) => {
  try {
    return execFileSync('git', argv, { cwd: ROOT, encoding: 'utf8' }).trim()
  } catch {
    return null
  }
}

const identity = {
  package: pkg.name,
  version: pkg.version,
  git: {
    commit: git(['rev-parse', 'HEAD']),
    // Branch matters here: several packages in this family ship from a feature
    // branch rather than main, so "main" is not a safe assumption about what
    // was released.
    branch: git(['rev-parse', '--abbrev-ref', 'HEAD']),
    dirty: (git(['status', '--porcelain']) || '') !== '',
  },
  toolchain: {
    node: process.version,
    openssl: process.versions.openssl,
    platform: `${process.platform}-${process.arch}`,
  },
  generatedAt: new Date().toISOString(),
}
write('01-identity.json', JSON.stringify(identity, null, 2) + '\n')

// -- 2. the primitives actually installed ------------------------------------

const PRIMITIVES = 'kxco-post-quantum'
const declared =
  (pkg.dependencies || {})[PRIMITIVES] ?? (pkg.peerDependencies || {})[PRIMITIVES] ?? null

let primitives = null

if (declared !== null) {
  const manifestPath = join(ROOT, 'node_modules', PRIMITIVES, 'package.json')
  if (existsSync(manifestPath)) {
    const installed = JSON.parse(readFileSync(manifestPath, 'utf8'))
    let backend = null
    try {
      const mod = await import(PRIMITIVES)
      backend = typeof mod.backend === 'function' ? mod.backend() : null
    } catch {
      // Older primitives had no backend(). Absence is recorded as null rather
      // than guessed at.
    }
    const exact = declared === installed.version
    primitives = {
      declared,
      resolved: installed.version,
      exact,
      backend,
      note: exact
        ? 'Declared exactly. The version assessed is the version that runs.'
        : `Declared as a range (${declared}). This bundle records ${installed.version}, ` +
          'which is what was installed here. Another install of this same package ' +
          'version may resolve differently, so an assessment that does not name the ' +
          'resolved version has not named the configuration.',
      conformance:
        `NIST ACVP vectors and the cross-implementation interoperability matrix are ` +
        `evidence of ${PRIMITIVES} and not of this package. They are published in ` +
        `that package's own bundle and are not repeated here.`,
    }
  } else {
    primitives = {
      declared,
      resolved: null,
      note: 'not installed; run npm install before building evidence',
    }
  }
  write('02-primitives.json', JSON.stringify(primitives, null, 2) + '\n')
}

// -- 3. this package's own tests ---------------------------------------------

const tests = run('tests', 'npm', ['test'], { optional: true })
if (tests !== null) write('03-tests.txt', tests)

// -- 4. supply chain ---------------------------------------------------------

const sbom = run(
  'sbom',
  'npm',
  ['sbom', '--sbom-format', 'cyclonedx', '--sbom-type', 'library'],
  { optional: true },
)
if (sbom !== null) write('04-sbom.cyclonedx.json', sbom)

const signatures = run('npm-audit-signatures', 'npm', ['audit', 'signatures'], { optional: true })
if (signatures !== null) write('05-npm-audit-signatures.txt', signatures)

// -- 5. the documents --------------------------------------------------------

const docs = ['ASSESSMENT.md', 'SECURITY.md', 'THREAT-MODEL.md']
const copied = []
for (const doc of docs) {
  const from = join(ROOT, doc)
  if (existsSync(from)) {
    copyFileSync(from, join(outDir, `06-${doc}`))
    copied.push(doc)
  }
}

write(
  'README.md',
  `# Evidence bundle: ${pkg.name} ${pkg.version}

Generated by \`scripts/build-evidence.mjs\` on ${identity.generatedAt}, from commit
${identity.git.commit ?? 'unknown'} on branch ${identity.git.branch ?? 'unknown'}${identity.git.dirty ? ', working tree dirty' : ''}.

| File | What it is |
|---|---|
| \`00-MANIFEST.json\` | Every command that produced this bundle, and a SHA-256 of every file in it |
| \`01-identity.json\` | Package, version, commit, branch, runtime |
| \`02-primitives.json\` | The ${PRIMITIVES} version **actually installed**, not the range declared |
| \`03-tests.txt\` | This package's own test run |
| \`04-sbom.cyclonedx.json\` | CycloneDX SBOM of the installed tree |
| \`05-npm-audit-signatures.txt\` | Registry signature verification |
| \`06-*\` | ${copied.length ? copied.join(', ') : 'no documents were found to copy'} |

## What this bundle is not

It carries no algorithm conformance evidence. This package does not implement
ML-DSA, ML-KEM or SLH-DSA. It calls ${PRIMITIVES}, which runs the NIST ACVP
vectors and the cross-implementation interoperability matrix and publishes them
in its own bundle. Read that one alongside this.

Restating a conformance claim here would invite you to count it twice.

## The version that matters

\`02-primitives.json\` records the resolved version, because a declared range is
not a configuration. Where \`exact\` is false, another install of this same
package version may run different primitives, and any claim made about this
bundle applies to the resolved version named in it.
`,
)

// -- 6. manifest -------------------------------------------------------------

const digests = {}
for (const name of readdirSync(outDir).sort()) {
  if (name === '00-MANIFEST.json') continue
  digests[name] =
    'sha256:' + createHash('sha256').update(readFileSync(join(outDir, name))).digest('hex')
}

const manifest = {
  subject: { package: pkg.name, version: pkg.version },
  ...identity,
  primitives,
  documents: copied,
  digests,
  scope:
    'What this package does, what it depends on, and what it was tested against. ' +
    'Algorithm conformance belongs to the primitives package and is referenced ' +
    'rather than restated.',
  attestation:
    'Self-generated and reproducible. Every result here came from a command recorded ' +
    'in `steps`, runnable against this commit. It is not third-party attestation and ' +
    'should not be read as any.',
  steps,
}
write('00-MANIFEST.json', JSON.stringify(manifest, null, 2) + '\n')

const failed = steps.filter((s) => !s.ok)
console.log(`evidence written to ${outDir}`)
console.log(`  package:    ${pkg.name} ${pkg.version}`)
if (primitives) {
  console.log(`  primitives: ${primitives.declared} resolved to ${primitives.resolved ?? 'NOT INSTALLED'}`)
}
console.log(`  steps:      ${steps.length - failed.length}/${steps.length} completed`)
if (failed.length) console.log(`  FAILED:     ${failed.map((s) => s.name).join(', ')}`)
console.log(`  files:      ${Object.keys(digests).length + 1}`)
