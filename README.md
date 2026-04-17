# Linux Visualisation Lab

Two browser-based simulators for teaching Linux access control:

1. **Linux Permissions** — classic `rwx` / owner-group-other model with `chmod`
2. **ACL Bouncer** — POSIX ACLs (`setfacl`, named users/groups, mask) as a nightclub door metaphor

Everything is plain HTML/CSS/JS. No build step, no dependencies.

---

## How to run

You need a local web server (the pages use JS modules which browsers refuse to load from `file://`).

### Option A — Python (built in on macOS/Linux)

```bash
cd "linux visualisation"
python3 -m http.server 8765
```

Then open **[Linux-Permissions-simulation](https://scaler00.github.io/python-Simulation/)** in a browser.

### Option B — Node

```bash
npx http-server . -p 8765
```

### Option C — VS Code

Install the **Live Server** extension, right-click `index.html`, "Open with Live Server".

---

## Project layout

```
linux visualisation/
├── index.html                       ← landing hub (pick a simulator)
├── README.md
├── Linux Permissions simulation/
│   ├── index.html
│   ├── app.js
│   └── styles.css
└── ACL Bouncer simulation/
    ├── index.html
    ├── acl.js
    ├── acl.css
    └── styles.css
```

The hub at `/` links to both simulators. Each simulator also has a tab in its header to hop to the other.

---

## 1. Linux Permissions

**URL:** `/Linux Permissions simulation/`

### Mode 1 · Sandbox
Free-play. No wrong answers.

- Click any of the 9 permission bits (r/w/x for user, group, others) to toggle them.
- Octal (e.g. `754`) and `ls -l` line update live.
- Every toggle writes a line to the **command log** showing both forms:
  `$ chmod u+x vault.txt  ≡  chmod 754 vault.txt`
- Click **cat / write / ./run** under each character (Alice, Bob, Guest, www-data) to see who succeeds and who gets `permission denied`.

### Mode 2 · Challenge
8 scored levels. Each gives a story + a goal; you type a real `chmod` command.

- Accepts both octal (`chmod 750 app.py`) and symbolic (`chmod u+rwx,g+rx`).
- **Symbolic bonus:** +3 points per level for using symbolic form (encodes the "prefer symbolic" DevOps style recommendation).
- Scoring: 10 points on first try, 7 on second, 4 on third, 3 after.
- 3+ attempts on a level flags it in the weak-spots report.
- Levels progress from pure mechanics → web/deploy contexts → recursive/SUID concepts → final synthesis.

### Weak Spots tab
After completing the challenge:
- Per-level attempt counts visualized as bars (green/amber/red).
- List of concepts to revisit — exactly what to cover in the next live session.
- Restart button resets state.

---

## 2. ACL Bouncer

**URL:** `/ACL Bouncer simulation/`

The bouncer at a nightclub door evaluates an ACL in 4 stages:

1. **Owner** — is this the file owner? Use owner perms. Mask does NOT apply.
2. **Named user** — is there a `user:alice:…` entry? Use those perms ∩ mask.
3. **Group** — owning group OR any named group. If ANY matching group grants the bit (after mask), ALLOW.
4. **Other** — fallback.

Once a stage matches, later stages are skipped. That's the core teaching point.

### Sandbox
- Edit the ACL rows on the left: toggle bits, add `user:` or `group:` entries, adjust the mask, remove entries.
- Every edit emits the equivalent `setfacl` command in the log.
- Pick a visitor (Alice, Bob, Carol, Dave, Guest) and an action (read/write/exec).
- Right panel shows:
  - The door (green = ALLOW, red = DENY).
  - The 4-stage walkthrough — matched stage highlighted green, skipped stages faded.
  - Per-stage reasoning (e.g. `group:auditors:r-- ∩ mask(rwx) = r--`).

### Predict mode
7 preset rounds that stress-test each stage and the mask:

| Round | Concept |
|-------|---------|
| 1 | Simple group grant via owning group |
| 2 | Named user beats group |
| 3 | Mask strips a permission the group had |
| 4 | Named group grants what owning group doesn't |
| 5 | Multiple group memberships — need only one to grant |
| 6 | Owner bypasses the mask entirely |
| 7 | Walk-in falls all the way to "other" |

Flow: read the ACL → predict **ALLOW** or **DENY** → reveal shows the bouncer's walk + a teaching note. Score = correct predictions / rounds.

---

## Suggested teaching flow

1. Start in **Linux Permissions · Sandbox** — anchor the owner/group/other model.
2. Move to **Linux Permissions · Challenge** — students convert natural language requirements to `chmod` commands.
3. Review the **Weak Spots** report as a class; revisit flagged concepts live.
4. Pivot to **ACL Bouncer · Sandbox** by showing a case classic perms can't express (e.g. "Carol from auditors needs read, but she's not in devteam"). Demonstrate adding a named-user or named-group entry.
5. Finish with **ACL Bouncer · Predict** as a quick formative check.

---

## Extending

- **Add a level:** append to the `LEVELS` array in `Linux Permissions simulation/app.js`. Each level is `{ id, title, story, goal, file, startPerms, target, hint, note? }`.
- **Add a predict round:** append to the array in `buildRounds()` in `ACL Bouncer simulation/acl.js`. Each round is `{ title, setup, guest, action, teach }`.
- **Add a character:** add an entry to `GUESTS` in `acl.js` (id, name, role, avatar class, groups array) — the bouncer logic will pick them up automatically.

No bundler. Reload the browser after editing.
# Linux-Permissions-simulation
