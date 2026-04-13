// Linux Permissions — Sandbox + Challenge
// Single-file logic. Pure, testable helpers at the top.

// ---------- Permission model ----------
const SCOPES = ['u', 'g', 'o'];
const BITS = ['r', 'w', 'x'];

const emptyPerms = () => ({ u: { r: 0, w: 0, x: 0 }, g: { r: 0, w: 0, x: 0 }, o: { r: 0, w: 0, x: 0 } });

function permsFromOctal(octal) {
  const s = String(octal).padStart(3, '0').slice(-3);
  const p = emptyPerms();
  SCOPES.forEach((sc, i) => {
    const n = parseInt(s[i], 10);
    p[sc].r = (n & 4) ? 1 : 0;
    p[sc].w = (n & 2) ? 1 : 0;
    p[sc].x = (n & 1) ? 1 : 0;
  });
  return p;
}

function permsToOctal(p) {
  return SCOPES.map(s => (p[s].r * 4) + (p[s].w * 2) + (p[s].x * 1)).join('');
}

function permsToSymbolic(p) {
  return SCOPES.map(s => BITS.map(b => p[s][b] ? b : '-').join('')).join('');
}

function lsLine(filename, p, owner, group) {
  return `-${permsToSymbolic(p)}  1 ${owner} ${group}  42 Apr 13  ${filename}`;
}

// actor role: 'u' owner, 'g' group, 'o' others
function actorRole(actor, owner, group) {
  if (actor === owner) return 'u';
  if (actor === 'bob' && group === 'devteam') return 'g';
  if (actor === 'www' && group === 'www-data') return 'g';
  return 'o';
}

function canAct(actor, action, p, owner, group) {
  const role = actorRole(actor, owner, group);
  const bit = action === 'read' ? 'r' : action === 'write' ? 'w' : 'x';
  return p[role][bit] === 1;
}

// ---------- chmod parser (octal + symbolic) ----------
// Returns { perms, symbolic: bool } or { error }
function applyChmod(cmd, currentPerms) {
  const trimmed = cmd.trim().replace(/^\$\s*/, '').replace(/\s+/g, ' ');
  const parts = trimmed.split(' ');
  if (parts[0] !== 'chmod') return { error: 'command must start with chmod' };
  if (parts.length < 3) return { error: 'usage: chmod MODE FILE' };
  const mode = parts[1];
  // Octal
  if (/^[0-7]{3,4}$/.test(mode)) {
    return { perms: permsFromOctal(mode.slice(-3)), symbolic: false };
  }
  // Symbolic — supports u+x, g-w, o=r, a+r, comma-separated; single chained clause
  const p = JSON.parse(JSON.stringify(currentPerms));
  const clauses = mode.split(',');
  for (const clause of clauses) {
    const m = clause.match(/^([ugoa]*)([+\-=])([rwx]*)$/);
    if (!m) return { error: `bad clause: ${clause}` };
    let [, who, op, bits] = m;
    if (!who) who = 'a';
    const targets = who.includes('a') ? ['u', 'g', 'o'] : who.split('');
    for (const t of targets) {
      if (op === '=') BITS.forEach(b => p[t][b] = 0);
      for (const b of bits) {
        if (op === '-') p[t][b] = 0;
        else p[t][b] = 1;
      }
    }
  }
  return { perms: p, symbolic: true };
}

// ---------- Challenge levels ----------
// Each level: story, goal (natural language), file (owner/group/name), startPerms, checker(perms), hint
const LEVELS = [
  {
    id: 1,
    title: 'Level 1 · First bits',
    story: 'Alice just created notes.txt. Right now nobody can do anything with it.',
    goal: 'Give the **owner** read and write. Leave group and others with nothing.',
    file: { name: 'notes.txt', owner: 'alice', group: 'devteam' },
    startPerms: '000',
    target: '600',
    hint: 'chmod 600 — owner=rw(4+2), group=0, others=0. Or symbolic: chmod u=rw',
  },
  {
    id: 2,
    title: 'Level 2 · Share with your team',
    story: 'Bob (in devteam) needs to read the notes too, but not edit them.',
    goal: 'Owner keeps read+write. Add **read** for the group. Others still nothing.',
    file: { name: 'notes.txt', owner: 'alice', group: 'devteam' },
    startPerms: '600',
    target: '640',
    hint: 'You already have 600. Add 40 (group read): chmod 640. Or: chmod g+r',
  },
  {
    id: 3,
    title: 'Level 3 · Deploy script',
    story: 'deploy.sh needs to be runnable by the owner. Without the execute bit, the shell refuses to run it.',
    goal: 'Owner should be able to **read, write, and execute**. Group can read+execute. Others: nothing.',
    file: { name: 'deploy.sh', owner: 'alice', group: 'devteam' },
    startPerms: '640',
    target: '750',
    hint: 'Owner 7 (rwx), group 5 (r-x), others 0: chmod 750. Or: chmod u+x,g+x',
  },
  {
    id: 4,
    title: 'Level 4 · Public web page',
    story: 'www-data (the web server) needs to read index.html to serve it to visitors.',
    goal: 'Owner: read+write. Group: read. **Others: read** (so www-data can serve it).',
    file: { name: 'index.html', owner: 'alice', group: 'devteam' },
    startPerms: '640',
    target: '644',
    hint: 'Others need read = 4. chmod 644. Or: chmod o+r',
  },
  {
    id: 5,
    title: 'Level 5 · Lock down secrets',
    story: 'db_password.conf was accidentally world-readable. Security flagged it.',
    goal: 'Only the **owner** should read or write. Strip all group and others permissions.',
    file: { name: 'db_password.conf', owner: 'root', group: 'root' },
    startPerms: '644',
    target: '600',
    hint: 'chmod 600 — or remove from group/others: chmod go-rwx',
  },
  {
    id: 6,
    title: 'Level 6 · Recursive fix',
    story: 'An intern ran chmod 777 on a whole directory of scripts. You need to normalize them to owner-only rwx.',
    goal: 'Set permissions to **700** on the script. (In real life you\'d add -R for recursion.)',
    file: { name: 'scripts/', owner: 'alice', group: 'devteam' },
    startPerms: '777',
    target: '700',
    hint: 'chmod 700 — remove all group+others. Real-world: chmod -R 700 scripts/',
    note: 'Concept: recursive chmod strips a whole tree. Dangerous if you point at /',
  },
  {
    id: 7,
    title: 'Level 7 · Spot the suspicious bit',
    story: 'You audit a server and see this: -rwsr-xr-x  root  root  /usr/bin/mytool. The "s" where owner-x should be is the SUID bit.',
    goal: 'Reset it to a normal executable: **755** (no SUID). Owner rwx, group/others r-x.',
    file: { name: '/usr/bin/mytool', owner: 'root', group: 'root' },
    startPerms: '755',  // for simplicity we skip rendering the s-bit, just test recognition
    target: '755',
    hint: 'In this simulator SUID is shown as a note — setting 755 is the safe baseline. chmod 755',
    note: 'Concept: SUID (4xxx) runs as the file owner regardless of who invokes it. Review recommendation: recognize, don\'t set.',
    freebie: true, // auto-pass if user types chmod 755 OR chmod 0755
  },
  {
    id: 8,
    title: 'Level 8 · Synthesis',
    story: 'New deploy: app.py must be executable by owner alice, readable+executable by devteam, and strictly invisible to others.',
    goal: 'Owner rwx, group r-x, others nothing. Figure out the number.',
    file: { name: 'app.py', owner: 'alice', group: 'devteam' },
    startPerms: '000',
    target: '750',
    hint: '7 (rwx) + 5 (r-x) + 0 = 750',
  },
];

// ---------- State ----------
const state = {
  mode: 'sandbox',
  sandbox: {
    perms: permsFromOctal('754'),
    owner: 'alice', group: 'devteam', filename: 'vault.txt',
    log: [], // { symbolic, octal }
  },
  challenge: {
    levelIdx: 0,
    perms: emptyPerms(),
    attempts: 0,
    score: 0,
    bonusCount: 0,
    attemptsByLevel: LEVELS.map(() => 0),
    doneByLevel: LEVELS.map(() => null), // null | 'ok' | 'fail'
    usedSymbolic: LEVELS.map(() => false),
    revealed: false,
  },
};

// ---------- Sandbox view ----------
function renderSandbox() {
  const app = document.getElementById('app');
  const tpl = document.getElementById('tpl-vault');
  app.innerHTML = '';
  const node = tpl.content.cloneNode(true);
  app.appendChild(node);

  const { perms, owner, group, filename } = state.sandbox;
  const root = app.querySelector('.vault');
  root.querySelector('[data-bind="filename"]').textContent = filename;
  root.querySelector('[data-bind="owner"]').textContent = owner;
  root.querySelector('[data-bind="group"]').textContent = group;

  // bit buttons
  root.querySelectorAll('.bits').forEach(bitsEl => {
    const scope = bitsEl.dataset.scope;
    bitsEl.querySelectorAll('.bit').forEach(b => {
      const bit = b.dataset.bit;
      b.classList.toggle('on', !!perms[scope][bit]);
      b.onclick = () => {
        const was = perms[scope][bit];
        state.sandbox.perms[scope][bit] = was ? 0 : 1;
        const op = was ? '-' : '+';
        const sym = `chmod ${scope}${op}${bit} ${filename}`;
        const oct = `chmod ${permsToOctal(state.sandbox.perms)} ${filename}`;
        state.sandbox.log.unshift({ sym, oct });
        if (state.sandbox.log.length > 6) state.sandbox.log.pop();
        renderSandbox();
      };
    });
  });

  root.querySelector('[data-bind="ls"]').textContent = lsLine(filename, perms, owner, group);
  root.querySelector('[data-bind="octal"]').textContent = permsToOctal(perms);

  // actors
  root.querySelectorAll('.char').forEach(charEl => {
    const actor = charEl.dataset.actor;
    charEl.querySelectorAll('.actions button').forEach(btn => {
      btn.onclick = () => {
        const action = btn.dataset.action;
        const ok = canAct(actor, action, perms, owner, group);
        const resEl = charEl.querySelector('.result');
        resEl.className = 'result ' + (ok ? 'ok' : 'bad');
        resEl.textContent = ok
          ? `✓ ${action} ok`
          : `✗ permission denied`;
      };
    });
  });

  // Command log — shows chmod equivalent for each bit toggle
  const logPanel = document.createElement('div');
  logPanel.className = 'panel';
  logPanel.style.marginTop = '20px';
  const logItems = state.sandbox.log.length
    ? state.sandbox.log.map((e, i) => `
        <div class="cmd-log-row${i === 0 ? ' latest' : ''}">
          <span class="cmd-log-prefix">$</span>
          <code class="cmd-log-sym">${e.sym}</code>
          <span class="cmd-log-eq">≡</span>
          <code class="cmd-log-oct">${e.oct}</code>
        </div>`).join('')
    : `<div style="color:var(--muted);font-size:13px;">Toggle any bit above — the equivalent <code>chmod</code> command appears here.</div>`;
  logPanel.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <h3 style="margin:0;font-size:14px;">Command log</h3>
      ${state.sandbox.log.length ? '<button class="hint-link" id="clear-log" style="margin:0;">clear</button>' : ''}
    </div>
    ${logItems}
  `;
  app.appendChild(logPanel);
  const clearBtn = document.getElementById('clear-log');
  if (clearBtn) clearBtn.onclick = () => { state.sandbox.log = []; renderSandbox(); };

  // Add a help panel below
  const help = document.createElement('div');
  help.className = 'panel';
  help.style.marginTop = '20px';
  help.innerHTML = `
    <h3 style="margin:0 0 8px;font-size:14px;">How to play</h3>
    <p style="margin:0;color:var(--muted);font-size:13px;line-height:1.6;">
      Click bits on the file card to toggle permissions. Then click actions on each character to see who succeeds and who gets <code>permission denied</code>.
      The <b>octal</b> (e.g. <code>754</code>) and <b>ls -l</b> line update live so you can build intuition for how they relate.
      No wrong answers here — explore. When you're ready, switch to <b>Mode 2 · Challenge</b>.
    </p>
  `;
  app.appendChild(help);
}

// ---------- Challenge view ----------
function renderChallenge() {
  const app = document.getElementById('app');
  const c = state.challenge;
  const lvl = LEVELS[c.levelIdx];
  app.innerHTML = '';

  const scoreBoard = document.createElement('div');
  scoreBoard.className = 'score-board';
  scoreBoard.innerHTML = `
    <div class="score-cell"><div class="v">${c.score}</div><div class="k">score</div></div>
    <div class="score-cell"><div class="v">${c.levelIdx + 1}/${LEVELS.length}</div><div class="k">level</div></div>
    <div class="score-cell"><div class="v">${c.bonusCount}</div><div class="k">symbolic bonus</div></div>
  `;
  app.appendChild(scoreBoard);

  const pips = document.createElement('div');
  pips.className = 'level-pips';
  LEVELS.forEach((_, i) => {
    const p = document.createElement('div');
    p.className = 'pip' + (c.doneByLevel[i] === 'ok' ? ' done' : c.doneByLevel[i] === 'fail' ? ' fail' : i === c.levelIdx ? ' active' : '');
    pips.appendChild(p);
  });
  app.appendChild(pips);

  const wrap = document.createElement('div');
  wrap.className = 'challenge-wrap';
  wrap.style.marginTop = '20px';

  // left: scenario + input
  const left = document.createElement('div');
  left.className = 'panel scenario';
  left.innerHTML = `
    <h2>${lvl.title}</h2>
    <div class="story">${lvl.story}</div>
    <div class="goal"><b>Goal:</b> ${lvl.goal.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')}</div>
    <div style="font-size:12px;color:var(--muted);font-family:var(--mono);">
      file: ${lvl.file.name} · owner ${lvl.file.owner} · group ${lvl.file.group} · current: ${permsToOctal(c.perms)}
    </div>
    <div class="cmd-input">
      <span class="prefix">$ </span>
      <input id="cmd" type="text" placeholder="chmod ... ${lvl.file.name}" autocomplete="off" />
      <button class="cmd-submit" id="submit">Run</button>
    </div>
    <div class="feedback" id="feedback"></div>
    <button class="hint-link" id="hint">Show hint</button>
    <div id="next-wrap"></div>
  `;

  // right: live preview
  const right = document.createElement('div');
  right.className = 'panel';
  right.innerHTML = `
    <div style="font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px;">current state</div>
    <code id="preview-ls" style="display:block;background:var(--panel-2);padding:10px;border-radius:6px;font-size:12px;margin-bottom:10px;">${lsLine(lvl.file.name, c.perms, lvl.file.owner, lvl.file.group)}</code>
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;">
      ${SCOPES.map(s => `
        <div class="perm-col">
          <div class="perm-label">${s === 'u' ? 'owner' : s === 'g' ? 'group' : 'others'}</div>
          <div style="font-family:var(--mono);font-size:18px;color:var(--accent);">${BITS.map(b => c.perms[s][b] ? b : '-').join('')}</div>
        </div>
      `).join('')}
    </div>
    ${lvl.note ? `<div style="margin-top:12px;font-size:12px;color:var(--warn);background:rgba(251,191,36,.08);padding:8px;border-radius:6px;">ℹ ${lvl.note}</div>` : ''}
  `;

  wrap.appendChild(left);
  wrap.appendChild(right);
  app.appendChild(wrap);

  // init perms to startPerms when entering the level
  if (c.attemptsByLevel[c.levelIdx] === 0 && !c.doneByLevel[c.levelIdx]) {
    c.perms = permsFromOctal(lvl.startPerms);
    right.querySelector('#preview-ls').textContent = lsLine(lvl.file.name, c.perms, lvl.file.owner, lvl.file.group);
  }

  const input = document.getElementById('cmd');
  const fb = document.getElementById('feedback');
  const submit = document.getElementById('submit');
  const hintBtn = document.getElementById('hint');
  const nextWrap = document.getElementById('next-wrap');

  input.focus();
  input.onkeydown = (e) => { if (e.key === 'Enter') submit.click(); };

  hintBtn.onclick = () => {
    fb.className = 'feedback hint';
    fb.textContent = '💡 ' + lvl.hint;
  };

  submit.onclick = () => {
    const cmd = input.value;
    const res = applyChmod(cmd, c.perms);
    c.attemptsByLevel[c.levelIdx] += 1;

    if (res.error) {
      fb.className = 'feedback bad';
      fb.textContent = '✗ ' + res.error;
      return;
    }

    c.perms = res.perms;
    const nowOctal = permsToOctal(c.perms);
    if (res.symbolic) c.usedSymbolic[c.levelIdx] = true;

    // update preview
    right.querySelector('#preview-ls').textContent = lsLine(lvl.file.name, c.perms, lvl.file.owner, lvl.file.group);
    right.querySelectorAll('.perm-col').forEach((col, i) => {
      const s = SCOPES[i];
      col.querySelector('div:last-child').textContent = BITS.map(b => c.perms[s][b] ? b : '-').join('');
    });

    if (nowOctal === lvl.target) {
      // success
      const attempts = c.attemptsByLevel[c.levelIdx];
      const base = Math.max(10 - (attempts - 1) * 3, 3); // 10, 7, 4, 3...
      let gained = base;
      let bonus = 0;
      if (c.usedSymbolic[c.levelIdx]) {
        bonus = 3;
        c.bonusCount += 1;
        gained += bonus;
      }
      c.score += gained;
      c.doneByLevel[c.levelIdx] = attempts > 3 ? 'fail' : 'ok';

      fb.className = 'feedback ok';
      fb.innerHTML = `✓ correct! <b>+${base}</b>${bonus ? ` <span class="bonus-tag">+${bonus} symbolic style bonus</span>` : ''}`;

      const isLast = c.levelIdx === LEVELS.length - 1;
      const nextBtn = document.createElement('button');
      nextBtn.className = 'next-btn';
      nextBtn.textContent = isLast ? 'See your weak-spots report →' : 'Next level →';
      nextBtn.onclick = () => {
        if (isLast) {
          state.mode = 'report';
        } else {
          c.levelIdx += 1;
        }
        render();
      };
      nextWrap.innerHTML = '';
      nextWrap.appendChild(nextBtn);
    } else {
      fb.className = 'feedback bad';
      const msg = c.attemptsByLevel[c.levelIdx] >= 3
        ? `✗ not quite — target is ${lvl.target}, you have ${nowOctal}. (3+ attempts will show up in your weak-spots report)`
        : `✗ not quite — currently ${nowOctal}, target is different. Attempt ${c.attemptsByLevel[c.levelIdx]}/3.`;
      fb.textContent = msg;
    }

    input.value = '';
  };
}

// ---------- Report view ----------
function renderReport() {
  const app = document.getElementById('app');
  const c = state.challenge;
  app.innerHTML = '';

  const panel = document.createElement('div');
  panel.className = 'panel';
  panel.innerHTML = `<h2 style="margin:0 0 6px;">Weak Spots Report</h2>
    <p style="color:var(--muted);margin:0 0 16px;font-size:13px;">Levels that took 3+ attempts — revisit these concepts in the next live session.</p>`;

  const maxAttempts = Math.max(1, ...c.attemptsByLevel);
  LEVELS.forEach((lvl, i) => {
    const attempts = c.attemptsByLevel[i];
    const completed = c.doneByLevel[i];
    const row = document.createElement('div');
    row.className = 'report-row';
    const barWidth = (attempts / maxAttempts) * 120;
    const barColor = attempts >= 3 ? 'var(--bad)' : attempts === 2 ? 'var(--warn)' : 'var(--ok)';
    row.innerHTML = `
      <div>
        <b>${lvl.title}</b>
        ${c.usedSymbolic[i] ? '<span class="bonus-tag">symbolic</span>' : ''}
      </div>
      <div style="color:var(--muted);font-size:12px;">
        ${completed ? `${attempts} attempt${attempts !== 1 ? 's' : ''}` : 'not attempted'}
        <span class="bar" style="width:${barWidth}px;background:${barColor};"></span>
      </div>
    `;
    panel.appendChild(row);
  });

  const summary = document.createElement('div');
  summary.className = 'panel';
  summary.style.marginTop = '16px';
  const weakSpots = LEVELS.filter((_, i) => c.attemptsByLevel[i] >= 3);
  summary.innerHTML = `
    <h3 style="margin:0 0 8px;font-size:14px;">Summary</h3>
    <div style="font-size:13px;line-height:1.8;">
      Final score: <b style="color:var(--accent);">${c.score}</b><br/>
      Used symbolic chmod: <b>${c.bonusCount}</b> / ${LEVELS.length} levels<br/>
      ${weakSpots.length ? `Concepts to revisit: <b style="color:var(--warn);">${weakSpots.map(l => l.title.replace(/^Level \d+ · /, '')).join(', ')}</b>` : 'No weak spots — clean run!'}
    </div>
    <button class="next-btn" style="margin-top:14px;" id="restart">Restart challenge</button>
  `;

  app.appendChild(panel);
  app.appendChild(summary);

  document.getElementById('restart').onclick = () => {
    state.challenge = {
      levelIdx: 0,
      perms: emptyPerms(),
      attempts: 0, score: 0, bonusCount: 0,
      attemptsByLevel: LEVELS.map(() => 0),
      doneByLevel: LEVELS.map(() => null),
      usedSymbolic: LEVELS.map(() => false),
      revealed: false,
    };
    state.mode = 'challenge';
    render();
  };
}

// ---------- Router ----------
function render() {
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.dataset.mode === state.mode);
  });
  if (state.mode === 'sandbox') renderSandbox();
  else if (state.mode === 'challenge') renderChallenge();
  else renderReport();
}

document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => { state.mode = t.dataset.mode; render(); };
});

render();
