# PingRoom duty conflicts

Find subjects who receive an incompatible combination of actions through their assigned or inherited roles. A named policy owner answers **Incompatible**, **Allowed** or **Unknown** for each supplied action pair in PingRoom. Code expands the frozen grant graph and exports conflicts with the role paths that explain each capability.

Use this to inspect an access export before review. The fictional craft-library example finds that Alex can both prepare and publish a listing through an inherited editor role. The starter produces a local diagnostic; it changes no access and certifies no compliance.

## Try it offline

Choose **Use this template**, clone your copy and install Node.js 22 or newer on macOS or Linux:

```sh
npm ci
npm test
npm run demo
```

The three demos cover an inherited conflict, Allowed pairs and an Unknown response. They use the real pinned `@pingroom/sdk` 0.8.0 with a local mock transport. Tests and demos need no credentials or network after installation. Live phone delivery is not tested.

The lockfile pins dependencies. `.npmrc` requests exact saves and a 14-day minimum release age where npm supports it. GitHub Actions checks installation, tests and demos on Node 22 and 24 with actions pinned to commits.

## Prepare a grant snapshot

```sh
cp examples/grants.json grants.json
cp config.example.json config.json
npm run preview
```

Adapt the copied JSON before collecting answers:

- `auditId`, `title`, `context`: identify the snapshot and explain the action-pair policy. The ASCII audit ID allows 32 characters; title and context allow 40 and 80 UTF-16 units.
- `actions`: 2–12 unique `{id,label}` records. Each action must represent one exact capability in your upstream export.
- `roles`: 1–12 `{id,label,inherits,grants}` records. An edge `A.inherits: [B]` means A includes B's grants, including B's inherited grants. Arrays contain distinct declared IDs and may be empty.
- `subjects`: 1–12 `{id,label,roles}` records. Assigned roles combine by union; an empty assignment is valid.
- `pairs`: 1–8 `{id,actions:[left,right]}` records. Supply the distinct action combinations whose policy needs a human answer. Reversed pairs are duplicates.

Entry IDs use 1–12 lowercase ASCII letters, digits, `_` or `-`, starting with a letter. The audit ID uses the same alphabet. Entry IDs cannot use reserved prototype names. Labels allow 32 UTF-16 units. Text must be well-formed, trimmed and single-line, with no control or formatting characters. Extra fields, duplicate IDs and unknown references fail validation.

Convert your provider export into this format in an adapter you control. The program does not fetch identities or permissions from that provider. Model resource-specific capabilities as separate action IDs only when the exported grants have that exact meaning. Do not flatten conditional permissions into unconditional grants.

The input uses positive grants only. Deny rules, active sessions, attribute-based conditions, resource scopes and dynamic separation of duties are outside the model. Cycles terminate through set closure; accepting a cycle here does not establish that a provider or an RBAC standard accepts it.

## Connect a policy owner

1. Install [PingRoom](https://pingroom.io/i). Run `npm run connect`, approve its printed pairing link, and grant a **standard private room** containing the policy owner. The connection needs room-list access and permission to create and read Questions in that room.
2. Run `npm run inspect`. Verify the intended person in the app and copy their exact member UUID into `config.json`. Names and local labels do not establish identity.
3. Run `npm start`. It creates one targeted question or reads the active question once. The owner has 15 minutes to answer. Run it again after an answer to observe it, then again to ask the next pair.

Pairing stores private `.pingroom/credentials.json` and resumes an existing pending link. To reuse a connection, copy `.env.example` to `.env` and set **both** `PINGROOM_TOKEN` and `PINGROOM_ROOM`, or supply both in the process environment. Partial or blank overrides fail; they never borrow the other value from saved credentials. `connect` and `inspect` do not send questions.

Questions send the title, context, candidate pair ID, action IDs and labels, participant UUID, and source/pair/policy hashes. Subject lists, role assignments and grant paths remain local. Keep sensitive material out of these fields.

## Inspect and export

```sh
npm run status
npm run report
npm run export
```

These commands are offline and work without credentials. `report` saves `.duties/report.json`; `export` writes `.duties/analysis.json` only after every candidate pair has a known attributed answer. A complete diagnostic may contain conflicts: callers must inspect `analysis.hasConflicts`, not just the exit code.

The output includes effective roles and actions per subject, pair classifications, violating subject/pair combinations, and one witness path per action. Paths start at an assigned role and end at a direct grant. Code chooses the shortest path, breaking ties by lexicographic role-ID path. Missing and Unknown answers withhold the whole analysis. Unlisted action pairs remain explicitly unassessed in `analysis.coverage`; Allowed says nothing about them.

Exit codes: `0` completed command, `1` validation or operation failure, `2` unresolved terminal answer or incomplete policy, `3` pending or ready for the next question, `4` uncertain question creation. A terminal answer can return `2` while the session is ready for another pair. The application never retries question creation automatically.

## Resume safely

Keep `grants.json`, `config.json`, `.duties/` and the original connection together. State binds their hashes, the calculation policy, target UUID, room, question identity, asking registration and answer times. Reordering sets preserves identity; changing content does not. Expired, cancelled or invalid answers remain unresolved, with no replacement question in the same session.

After a timeout or lost create response:

```sh
npm run status
npm run find-id
npm run recover -- EXACT_QUESTION_UUID
```

`find-id` searches a bounded recent question window. An empty result does not prove creation failed. `recover` checks the exact original question before accepting it; do not delete state to resend. If pairing creation is uncertain, inspect Connected Agents before archiving the pending pairing file.

Private files use mode `0600`, directories `0700`, atomic writes and an exclusive local lock. If a crash leaves a lock, confirm no process is using that directory before removing only the stale lock. Use persistent local storage and one writer; this is not a distributed or tamper-proof audit system. Credentials, inputs and generated evidence are ignored by Git.

For another snapshot, preserve this session and use a separate template checkout and connection setup. Integrate the exported diagnostic into your review UI or reporting job. Implement remediation, access changes or provider-specific verification in a separate adapter; the sample performs none.

MIT licensed. [Official SDK](https://github.com/pingroom/sdk).
