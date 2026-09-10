# dsh-plugin-vet · DSH 插件审视器

Vet a [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`) plugin straight from GitHub — **before** you install it.

Downloads the repository tarball, extracts it to a scratch directory, and reports what the package is made of. It never installs anything into a profile and never executes a single line of the plugin's code.

```
node dsh-plugin-vet.mjs icyaaaww/dsh-tool-failure-circuit-breaker
```

No dependencies. Node 22+ (global `fetch`).

## Why this exists

A `dsh` plugin is an ordinary npm package that the harness loads into its own process. Its entry point is called as `apply(ctx, config)` with a full cordis `Context`, so it runs with the harness's privileges:

- it can read `~/.dsh/.credentials.yaml`, where your provider API keys live
- it can read and write your filesystem
- it can open sockets, and Node's permission model has **no network switch** to stop it
- it can spawn processes

There is no plugin permission model, no enforced permission manifest, and no install-time prompt. The `permissions=` field that some `dsh://plugin/install?...` deep links carry is display-only — no code in the harness runtime reads it. The `settings → plugin inventory` page is an explicitly read-only projection with no provenance or permission concept.

So the only thing between a plugin and your machine is whether you read it first. This tool makes that cheap.

It also fixes a second, quieter mistake: **what lands in `node_modules` is the `package.json` `files` field, not the whole repository.** Auditing the wrong set of files is easy to do and easy to miss.

## Usage

```
node dsh-plugin-vet.mjs <owner/repo | github-url> [options]
```

| Option | Meaning |
|---|---|
| `--ref <ref>` | branch, tag, or commit sha (default: the repository's default branch) |
| `--out <dir>` | scratch directory (default: OS temp dir, falling back to `./.dsh-plugin-vet`) |
| `--keep` | keep the extracted tree so you can read it yourself |
| `--json` | machine-readable output |
| `-h`, `--help` | usage |

Accepted repo forms: `owner/repo`, `github.com/owner/repo`, `https://github.com/owner/repo`, optionally with `#ref`, `/tree/<ref>`, or a trailing `.git`.

`GITHUB_TOKEN` (or `GH_TOKEN`) is optional and only used for reads. Without it GitHub allows 60 API requests an hour, which a few runs will exhaust; a read-only token raises the limit. The token is sent to `api.github.com` and `codeload.github.com` and nowhere else.

## What it reports

**repository** — default branch, the resolved **commit sha**, licence, stars/forks, age, last push, archived flag, and the exact tarball URL and sha256. The commit is resolved from the symbolic ref because a branch name is not a pin, and a report you cannot reproduce later is worth much less. The report prints a ready-to-use pinned install spec:

```
pin install at : github:owner/repo#<40-char-sha>
```

**packages** — shown when the repository holds more than one package, which is common in this ecosystem: several independent plugins side by side, or a workspace root with the real packages in subdirectories. It lists every directory that contains a `package.json`, with its name, how many of its own files ship, whether it declares a bundle patch, and its hit counts — then repeats a manifest summary per package.

This matters because a repo-level view is actively misleading here. For a monorepo with no root `package.json`, a single-package report says "41 of 41 files ship", when the truth is four subdirectory packages shipping 13/15, 6/7, 3/7 and 5/8 files respectively — each installed separately, each with its own `cordis.patch.yml`. The repo-level verdict hides exactly the thing you need to look at.

**package** — name, version, licence, `type`, `main`/`exports`, `engines`, dependencies, and every `scripts` entry. Install-time scripts (`preinstall`, `install`, `postinstall`, `prepare`, `prepack`, `postpack`, `prepublishOnly`) are called out loudly with their command bodies, because that is code that runs on your machine at install time. Note that `pnpm >= 10` blocks dependency build scripts until you allowlist them in `pnpm-workspace.yaml` — do not allowlist before reading them.

**DSH bundle wiring** — whether the package declares `dsh.bundle.patch`, and what that patch does:

- *targeted overrides* — rows it patches by id. Rows that carry harness policy (`system-prompt`, `sandbox-policy`, `approval`, `permission`, `credentials`, `tools`, `agent-loop`, …) are flagged, since overriding or disabling them changes harness behaviour rather than adding a feature.
- *inserted rows* — new plugins it mounts into the profile layer stack.
- *`!!js` expressions* — cordis evaluates these when the config loads, which makes the config file executable code.

A package without `dsh.bundle.patch` installs as a plain dependency and never joins the layer stack; the report says so.

**what actually gets installed** — the files matching the `files` field, with size and sha256 each. Findings in files that never ship are excluded from the verdict.

**pattern scan** — line-attributed matches for dynamic code execution (`eval`, `new Function`, `vm.*`), `!!js`, child processes, credential/private-key paths, destructive filesystem calls, network egress, environment reads, base64/hex obfuscation, prompt-layer references, and file writes. Every hit is labelled with why it matters.

**verdict** — counts by severity, policy findings, and notes. Exit code is `0` when nothing high-severity fired, `1` when something did, `2` when the tool itself failed. Useful in CI.

## How to read the output

The most valuable section is usually **DSH bundle wiring**, because that is where a plugin's power is declared rather than implied. A plugin that inserts one row and touches nothing else is behaving the way a plugin should. A plugin that patches `sandbox-policy` or `approval` is asking for more than its stated purpose.

The second most valuable is **the `files` list**, because it tells you how many files you actually have to read. For a well-built small plugin that is often one file of a few hundred lines, which makes "read it before installing" a five-minute job rather than a research project.

Exit code `0` is **not** approval. It means no heuristic fired. Read the entry file.

## What it says about itself

Run it on this repository and it reports a couple of dozen high-severity hits. Read them, and all of them are false positives, for an instructive reason:

```
HIGH  credential-path     dsh-plugin-vet.mjs  .git-credentials
HIGH  credential-path     dsh-plugin-vet.mjs  id_rsa
HIGH  yaml-js-expression  dsh-plugin-vet.mjs  !!js
MED   network-egress      dsh-plugin-vet.mjs  fetch(
LOW   fs-write            dsh-plugin-vet.mjs  rmSync(
```

Every one comes from the tool's own rule table: the regexes match their own string literals, the `!!js` hits are the pattern definitions themselves, and the `rmSync` is the scratch-directory cleanup. It also correctly reports that the entry does not export `apply`, because this is not a cordis plugin.

(Line numbers omitted here because they drift every time the file grows — the tool prints current ones.)

That is the honest shape of a grep-based scan. A hit means *read this line*, not *this is malicious* — which is exactly why every hit is line-attributed. Read the lines.

## What it can't do — read this part

- **It is heuristic, not definitive.** It greps for shapes. Malicious behaviour written to look like ordinary code will not be flagged. It is a triage tool that tells you where to look, not a verdict.
- **No reachability analysis.** A hit inside a script that never runs is noise; the tool cannot tell you which functions actually execute. Both real findings and false positives come from this.
- **No YAML parse.** The patch analysis is an indentation-aware textual scan, chosen deliberately so the tool needs no dependencies — but read the patch file itself before trusting it.
- **It does not read the prompt payloads.** For a prompt-injection plugin, the interesting content is prose in a `.md` file, not code. The tool flags that the prompt layer is touched and stops there; judging the payload is your call.
- **No network inspection.** A plugin can exfiltrate over HTTP and nothing here would stop it. Inspect egress separately (a proxy, or Process Monitor on Windows).
- **Not a virus scanner.** No signatures, no sandbox execution.
- **Package discovery is by `package.json` presence.** Every directory containing one is treated as a package (`node_modules` excluded). It does not read `workspaces` globs, so a package whose manifest is renamed or generated at publish time is missed.

## A workflow it fits into

```sh
# 1. Vet first, in a throwaway directory. Read the report.
node dsh-plugin-vet.mjs owner/repo --keep

# 2. Read the entry file yourself. It is usually small.
$EDITOR .dsh-plugin-vet/owner-repo/index.js

# 3. If you still want it, install into a scratch profile — never your live one.
dsh plugin --profile scratch add github:owner/repo#<sha>
dsh --profile scratch --dump-config   # see exactly what it inserted

# 4. Only then move it to your real profile.
```

Pinning to the resolved sha in step 3 means a later `pnpm install` cannot silently pull different code.

## 中文说明

在安装 `dsh` 插件**之前**审查它。直接拉 GitHub tarball 解包检查，**不安装、不执行插件代码**。

为什么需要：`dsh` 插件就是普通 npm 包，被加载进 harness 进程，`apply(ctx, config)` 拿到完整 cordis `Context`，等于你的完整用户权限 —— 能读 `~/.dsh/.credentials.yaml`（API key 在里面）、读写文件、联网、起子进程。**没有插件权限模型，没有强制声明的权限清单，没有安装期确认**。某些安装深链里的 `permissions=` 字段只是展示，运行时没有任何代码读它；`设置 → 插件清单` 自己写明了是只读投影，没有 provenance 也没有权限概念。

另外它纠正一个容易搞错的点：**真正进 `node_modules` 的是 `package.json` 的 `files` 字段，不是整个仓库**。审错文件集合很容易发生。

可选的 `GITHUB_TOKEN` / `GH_TOKEN` 只用于读。不设的话 GitHub 每小时只给 60 次 API 调用，跑几次就用光了；给一个只读 token 就能提上限。token 只会发给 `api.github.com` 和 `codeload.github.com`。

输出的重点：

- **packages（monorepo 必看）** —— 仓库里有多个包时才出现。像 `Oh-My-DSH` 这种一个仓库塞四个独立插件的，仓库级视角会骗你：它说"41 个文件全都会装上"，真相却是四个子包分别装 13/15、6/7、3/7、5/8 个文件，各自带自己的 `cordis.patch.yml`、各自独立安装。这个表把每个包单独列出来，包括各自的高危/中危命中数。
- **DSH bundle wiring（最有价值）** —— 插件的权力在这里被*声明*。只插一行、不动别处的插件是本分；去 patch `sandbox-policy` / `approval` 的插件要的就不只是它声称的东西。`!!js` 表达式在加载配置时被求值，等于配置即代码。
- **what actually gets installed** —— 你真正需要读的文件有几个。写得好的小插件常常就一个文件几百行，读完只要几分钟。
- **退出码 `0` 不代表批准** —— 只代表启发式规则没命中。入口文件还是要自己读。

局限（诚实版）：纯启发式，会漏；没有可达性分析，所以既有漏报也有误报；patch 分析是文本扫描不是 YAML 解析；包发现只看 `package.json` 是否存在（不读 `workspaces` 通配），所以清单被改名或在发布时才生成的包会被漏掉；**不读提示词正文**（对提示词注入类插件，正文才是重点，工具只告诉你"它碰了提示词层"）；不做网络检测；不是杀毒软件。

## License

MIT
