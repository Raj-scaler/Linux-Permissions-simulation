// ACL Bouncer — nightclub metaphor for POSIX ACL evaluation.
//
// Evaluation order (what the bouncer walks through):
//   1. Owner match        → use owner perms, done.
//   2. Named user match   → use named perms ∩ mask, done.
//   3. Group match (owning group OR any named group)
//                         → union of matches, ∩ mask, done.
//                         (if ANY group entry grants it, ALLOW)
//   4. Other              → fallback.
//
// "Done" means once a stage matches, later stages are skipped — this is the
// core teaching point. We render the walk visually, stage by stage.

const BITS = ['r', 'w', 'x'];
const bitOf = (act) => act === 'read' ? 'r' : act === 'write' ? 'w' : 'x';

// --- Cast ---
const GUESTS = [
  { id: 'alice',   name: 'Alice',    role: 'owner',         emoji: '👩', avatar: 'a', groups: ['devteam'] },
  { id: 'bob',     name: 'Bob',      role: 'devteam',       emoji: '🧑', avatar: 'b', groups: ['devteam'] },
  { id: 'carol',   name: 'Carol',    role: 'auditor',       emoji: '👩‍💼', avatar: 'g', groups: ['auditors'] },
  { id: 'dave',    name: 'Dave',     role: 'contractor',    emoji: '🧔', avatar: 'w', groups: ['contractors', 'devteam'] },
  { id: 'guest',   name: 'Guest',    role: 'walk-in',       emoji: '🕶', avatar: 'g', groups: [] },
];

// --- Default file + ACL ---
// ACL shape:
// {
//   owner: 'alice',
//   ownerGroup: 'devteam',
//   entries: [  // named user/group entries
//     { type: 'user',  who: 'dave',       perms: { r:1, w:0, x:1 } },
//     { type: 'group', who: 'auditors',   perms: { r:1, w:0, x:0 } },
//   ],
//   basePerms: { u:{r,w,x}, g:{r,w,x}, o:{r,w,x} },
//   mask: { r:1, w:0, x:1 },
// }
function defaultACL() {
  return {
    owner: 'alice',
    ownerGroup: 'devteam',
    entries: [
      { type: 'user', who: 'dave', perms: { r: 1, w: 0, x: 1 } },
      { type: 'group', who: 'auditors', perms: { r: 1, w: 0, x: 0 } },
    ],
    basePerms: {
      u: { r: 1, w: 1, x: 0 },
      g: { r: 1, w: 0, x: 0 },
      o: { r: 0, w: 0, x: 0 },
    },
    mask: { r: 1, w: 1, x: 0 },
  };
}

// --- The evaluation walk ---
// Returns an array of stage results, each with { num, label, matched, verdict, reason, skipped }
// The verdict at the first matched stage is the final one.
function evaluate(acl, guest, action) {
  const bit = bitOf(action);
  const stages = [];

  // Stage 1: owner
  const ownerMatch = guest.id === acl.owner;
  stages.push({
    num: 1,
    label: 'Owner check',
    desc: `Is the visitor ${acl.owner}?`,
    matched: ownerMatch,
    verdict: ownerMatch ? (acl.basePerms.u[bit] ? 'allow' : 'deny') : null,
    reason: ownerMatch
      ? `Owner perms: ${permStr(acl.basePerms.u)} → ${bit} ${acl.basePerms.u[bit] ? 'granted' : 'not granted'}. Mask does NOT apply to owner.`
      : `Not the owner (${guest.name} ≠ ${acl.owner}). Skip.`,
  });
  if (ownerMatch) {
    return finalize(stages);
  }

  // Stage 2: named user
  const namedUser = acl.entries.find(e => e.type === 'user' && e.who === guest.id);
  stages.push({
    num: 2,
    label: 'Named user ACL',
    desc: `Is there a user: entry for ${guest.id}?`,
    matched: !!namedUser,
    verdict: namedUser ? (effective(namedUser.perms, acl.mask)[bit] ? 'allow' : 'deny') : null,
    reason: namedUser
      ? `user:${namedUser.who}:${permStr(namedUser.perms)} ∩ mask(${permStr(acl.mask)}) = ${permStr(effective(namedUser.perms, acl.mask))}`
      : `No named entry for ${guest.id}. Skip.`,
  });
  if (namedUser) return finalize(stages);

  // Stage 3: group (owning group + any named group the guest is in)
  const groupMatches = [];
  if (guest.groups.includes(acl.ownerGroup)) {
    groupMatches.push({ who: acl.ownerGroup, source: 'owning group', perms: acl.basePerms.g });
  }
  for (const e of acl.entries) {
    if (e.type === 'group' && guest.groups.includes(e.who)) {
      groupMatches.push({ who: e.who, source: 'named group', perms: e.perms });
    }
  }
  const groupMatched = groupMatches.length > 0;
  let groupVerdict = null;
  let groupReason = `${guest.name} is not in any group on this ACL. Skip.`;
  if (groupMatched) {
    // POSIX rule: if ANY matching group entry grants the bit (after mask), ALLOW.
    let allowed = false;
    const detail = groupMatches.map(gm => {
      const eff = effective(gm.perms, acl.mask);
      if (eff[bit]) allowed = true;
      return `${gm.source} ${gm.who}:${permStr(gm.perms)} ∩ mask = ${permStr(eff)}`;
    }).join(' · ');
    groupVerdict = allowed ? 'allow' : 'deny';
    groupReason = detail + (allowed ? ' → at least one group grants it ✓' : ' → no group grants it');
  }
  stages.push({
    num: 3,
    label: 'Group checks',
    desc: `Does any group entry (owning or named) apply?`,
    matched: groupMatched,
    verdict: groupVerdict,
    reason: groupReason,
  });
  if (groupMatched) return finalize(stages);

  // Stage 4: other
  stages.push({
    num: 4,
    label: 'Other (fallback)',
    desc: `Nothing else matched — use "other" perms.`,
    matched: true,
    verdict: acl.basePerms.o[bit] ? 'allow' : 'deny',
    reason: `other perms: ${permStr(acl.basePerms.o)} → ${bit} ${acl.basePerms.o[bit] ? 'granted' : 'not granted'}.`,
  });
  return finalize(stages);
}

function finalize(stages) {
  // mark later stages as skipped (for rendering)
  let stopped = false;
  const out = stages.map(s => {
    if (stopped) return { ...s, skipped: true };
    if (s.matched) stopped = true;
    return s;
  });
  // fill in unreached stages as placeholders so the UI always shows 4
  const labels = [
    { num: 1, label: 'Owner check', desc: 'Is the visitor the file owner?' },
    { num: 2, label: 'Named user ACL', desc: 'Specific user: entry?' },
    { num: 3, label: 'Group checks', desc: 'Owning or named group?' },
    { num: 4, label: 'Other (fallback)', desc: 'Everyone else.' },
  ];
  const seen = new Set(out.map(s => s.num));
  for (const l of labels) {
    if (!seen.has(l.num)) out.push({ ...l, matched: false, verdict: null, reason: 'Not reached — earlier stage matched.', skipped: true });
  }
  out.sort((a, b) => a.num - b.num);
  return out;
}

function permStr(p) { return BITS.map(b => p[b] ? b : '-').join(''); }
function effective(perms, mask) {
  return { r: perms.r & mask.r, w: perms.w & mask.w, x: perms.x & mask.x };
}

function finalVerdict(stages) {
  const matched = stages.find(s => s.matched && !s.skipped);
  return matched?.verdict || 'deny';
}

// --- State ---
const state = {
  mode: 'sandbox',
  acl: defaultACL(),
  filename: 'club.log',
  selectedGuest: 'bob',
  action: 'read',
  setfaclLog: [],
  // challenge
  ch: {
    idx: 0,
    score: 0,
    rounds: buildRounds(),
    picked: null,   // 'allow'|'deny'
    revealed: false,
  },
};

function buildRounds() {
  // A handful of preset scenarios that stress each stage + mask interaction.
  return [
    {
      title: 'Round 1 · Simple group grant',
      setup: {
        ...defaultACL(),
        basePerms: { u: { r:1,w:1,x:0 }, g: { r:1,w:0,x:0 }, o: { r:0,w:0,x:0 } },
        entries: [],
        mask: { r:1, w:1, x:0 },
      },
      guest: 'bob', action: 'read',
      teach: 'Bob is in devteam (the owning group). Group has r. Mask allows r. Stage 3 matches.',
    },
    {
      title: 'Round 2 · Named user bypass',
      setup: {
        ...defaultACL(),
        entries: [{ type:'user', who:'dave', perms:{r:1,w:1,x:0} }],
        mask: {r:1, w:1, x:0},
      },
      guest: 'dave', action: 'write',
      teach: 'Dave has a user: entry with rw-. Mask allows w. Stage 2 matches before group.',
    },
    {
      title: 'Round 3 · Mask blocks a group',
      setup: {
        ...defaultACL(),
        basePerms: { u:{r:1,w:1,x:0}, g:{r:1,w:1,x:0}, o:{r:0,w:0,x:0} },
        entries: [],
        mask: { r:1, w:0, x:0 },  // mask strips w
      },
      guest: 'bob', action: 'write',
      teach: 'Group grants w but the MASK strips it. Effective: r--. Deny.',
    },
    {
      title: 'Round 4 · Named group grants what base group does not',
      setup: {
        ...defaultACL(),
        basePerms: { u:{r:1,w:1,x:0}, g:{r:0,w:0,x:0}, o:{r:0,w:0,x:0} },
        entries: [{ type:'group', who:'auditors', perms:{r:1,w:0,x:0} }],
        mask: {r:1, w:1, x:1},
      },
      guest: 'carol', action: 'read',
      teach: 'Owning group gives nothing, but Carol is in auditors (named group r--). Stage 3 union → allow.',
    },
    {
      title: 'Round 5 · Multiple group memberships — ANY grants = allow',
      setup: {
        ...defaultACL(),
        basePerms: { u:{r:1,w:1,x:0}, g:{r:0,w:0,x:0}, o:{r:0,w:0,x:0} },
        entries: [{ type:'group', who:'contractors', perms:{r:0,w:0,x:0} }],
        mask: {r:1, w:1, x:1},
      },
      guest: 'dave', action: 'read',
      teach: 'Dave is in both devteam (owning, ---) and contractors (named, ---). No group grants r. Falls through → other (---). Deny.',
    },
    {
      title: 'Round 6 · Owner ignores mask',
      setup: {
        ...defaultACL(),
        basePerms: { u:{r:1,w:1,x:1}, g:{r:0,w:0,x:0}, o:{r:0,w:0,x:0} },
        entries: [],
        mask: { r:0, w:0, x:0 },
      },
      guest: 'alice', action: 'write',
      teach: 'Alice is the owner — stage 1 matches. Mask does NOT apply to owner. Allow.',
    },
    {
      title: 'Round 7 · Walk-in at the back',
      setup: {
        ...defaultACL(),
        basePerms: { u:{r:1,w:1,x:0}, g:{r:1,w:0,x:0}, o:{r:1,w:0,x:0} },
        entries: [],
        mask: {r:1, w:1, x:1},
      },
      guest: 'guest', action: 'read',
      teach: 'Guest is nobody special — falls all the way to stage 4 (other). other has r → allow.',
    },
  ];
}

// --- Rendering ---
function render() {
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.dataset && t.dataset.mode === state.mode);
  });
  const app = document.getElementById('app');
  app.innerHTML = '';
  if (state.mode === 'sandbox') renderSandbox(app);
  else renderChallenge(app);
}

function renderSandbox(app) {
  const wrap = document.createElement('div');
  wrap.className = 'club-wrap';

  // LEFT: ACL editor
  const left = document.createElement('div');
  left.className = 'acl-list';
  left.innerHTML = renderAclEditor(state.acl, state.filename);

  // RIGHT: club scene
  const right = document.createElement('div');
  right.className = 'panel club-scene';
  const guest = GUESTS.find(g => g.id === state.selectedGuest);
  const stages = evaluate(state.acl, guest, state.action);
  const verdict = finalVerdict(stages);

  right.innerHTML = `
    <div class="bouncer">🕴️</div>
    <div class="door ${verdict === 'allow' ? 'open' : 'shut'}">
      <div class="door-label">${verdict === 'allow' ? 'ALLOW ✓' : 'DENY ✗'}</div>
    </div>
    <div style="color:var(--muted);font-size:12px;margin-top:8px;">file: <code>${state.filename}</code></div>

    <div style="margin-top:14px;font-size:12px;color:var(--muted);text-align:left;">Pick a visitor:</div>
    <div class="queue">
      ${GUESTS.map(g => `
        <div class="guest ${g.id === state.selectedGuest ? 'active' : ''}" data-guest="${g.id}">
          <div class="avatar ${g.avatar}">${g.name[0]}</div>
          <div class="g-name">${g.name}</div>
          <div class="g-role">${g.role}</div>
        </div>
      `).join('')}
    </div>

    <div class="action-select">
      ${['read', 'write', 'exec'].map(a => `
        <button data-action="${a}" class="${a === state.action ? 'on' : ''}">${a}</button>
      `).join('')}
    </div>

    <div class="stages">
      ${stages.map(s => `
        <div class="stage ${s.skipped ? 'skipped' : ''} ${s.matched && !s.skipped ? 'matched' : ''}">
          <div class="num">${s.num}</div>
          <div>
            <div class="label">${s.label} <span class="desc">${s.desc}</span></div>
            <div class="desc" style="margin-top:2px;">${s.reason}</div>
          </div>
          <div class="verdict ${s.verdict || ''}">${s.matched && !s.skipped ? (s.verdict === 'allow' ? '✓ ALLOW' : '✗ DENY') : ''}</div>
        </div>
      `).join('')}
    </div>
  `;

  wrap.appendChild(left);
  wrap.appendChild(right);
  app.appendChild(wrap);

  wireSandbox();
}

function renderAclEditor(acl, filename) {
  const rows = [];
  // owner
  rows.push(renderRow('user::', acl.owner + ' (owner)', acl.basePerms.u, null, false));
  // named users
  acl.entries.filter(e => e.type === 'user').forEach((e, i) => {
    rows.push(renderRow('user:', e.who, e.perms, { type: 'user', idx: acl.entries.indexOf(e) }, true));
  });
  // owning group
  rows.push(renderRow('group::', acl.ownerGroup, acl.basePerms.g, null, false));
  // named groups
  acl.entries.filter(e => e.type === 'group').forEach((e) => {
    rows.push(renderRow('group:', e.who, e.perms, { type: 'group', idx: acl.entries.indexOf(e) }, true));
  });
  // mask
  rows.push(`
    <div class="acl-row mask">
      <span class="tag">mask::</span>
      <span class="who">caps group & named entries</span>
      <div class="perm-toggles">
        ${BITS.map(b => `<button class="bit ${acl.mask[b] ? 'on' : ''}" data-scope="mask" data-bit="${b}">${b}</button>`).join('')}
      </div>
      <span></span>
    </div>
  `);
  // other
  rows.push(renderRow('other::', 'everyone else', acl.basePerms.o, null, false));

  const setfaclItems = state.setfaclLog.length
    ? state.setfaclLog.map((c, i) => `<div class="cmd-log-row${i === 0 ? ' latest' : ''}"><span class="cmd-log-prefix">$</span><code class="cmd-log-sym">${c}</code></div>`).join('')
    : `<div style="color:var(--muted);font-size:12px;">Edit any row — the equivalent <code>setfacl</code> appears here.</div>`;

  return `
    <h3>ACL — the guest list</h3>
    <div class="sub">getfacl ${filename}</div>
    ${rows.join('')}
    <div class="add-rule">
      <select id="new-type">
        <option value="user">user:</option>
        <option value="group">group:</option>
      </select>
      <input id="new-who" placeholder="name (e.g. carol or auditors)" />
      <div class="perm-toggles" style="justify-content:flex-start;">
        ${BITS.map(b => `<button class="bit" data-newbit="${b}">${b}</button>`).join('')}
      </div>
      <button id="add-rule">Add</button>
    </div>
    <div class="setfacl-log">
      <h3 style="font-size:13px;margin:14px 0 6px;">setfacl log</h3>
      ${setfaclItems}
    </div>
  `;
}

function renderRow(tag, who, perms, removable, editable) {
  return `
    <div class="acl-row ${editable ? '' : 'effective'}">
      <span class="tag">${tag}</span>
      <span class="who">${who}</span>
      <div class="perm-toggles">
        ${BITS.map(b => `<button class="bit ${perms[b] ? 'on' : ''}" data-row='${JSON.stringify(removable ? { type: 'entry', entryType: removable.type, idx: removable.idx } : { type: 'base', scope: tag.startsWith('user') ? 'u' : tag.startsWith('group') ? 'g' : 'o' })}' data-bit="${b}">${b}</button>`).join('')}
      </div>
      ${removable ? `<button class="rm" data-rm='${JSON.stringify(removable)}'>×</button>` : '<span></span>'}
    </div>
  `;
}

function wireSandbox() {
  // Guest picks
  document.querySelectorAll('.guest').forEach(el => {
    el.onclick = () => { state.selectedGuest = el.dataset.guest; render(); };
  });
  // Action picks
  document.querySelectorAll('[data-action]').forEach(el => {
    el.onclick = () => { state.action = el.dataset.action; render(); };
  });
  // Bit toggles on rows
  document.querySelectorAll('.acl-row .bit[data-row]').forEach(b => {
    b.onclick = () => {
      const info = JSON.parse(b.dataset.row);
      const bit = b.dataset.bit;
      applyBitToggle(info, bit);
      render();
    };
  });
  // Mask toggle
  document.querySelectorAll('.acl-row .bit[data-scope="mask"]').forEach(b => {
    b.onclick = () => {
      const bit = b.dataset.bit;
      const was = state.acl.mask[bit];
      state.acl.mask[bit] = was ? 0 : 1;
      state.setfaclLog.unshift(`setfacl -m m::${permStr(state.acl.mask)} ${state.filename}`);
      trim();
      render();
    };
  });
  // Remove rule
  document.querySelectorAll('.rm').forEach(b => {
    b.onclick = () => {
      const info = JSON.parse(b.dataset.rm);
      const entry = state.acl.entries[info.idx];
      state.setfaclLog.unshift(`setfacl -x ${entry.type}:${entry.who} ${state.filename}`);
      state.acl.entries.splice(info.idx, 1);
      trim();
      render();
    };
  });
  // Add new rule
  const newBits = { r: 0, w: 0, x: 0 };
  document.querySelectorAll('[data-newbit]').forEach(b => {
    b.onclick = () => {
      const bit = b.dataset.newbit;
      newBits[bit] = newBits[bit] ? 0 : 1;
      b.classList.toggle('on');
    };
  });
  const addBtn = document.getElementById('add-rule');
  if (addBtn) addBtn.onclick = () => {
    const type = document.getElementById('new-type').value;
    const who = document.getElementById('new-who').value.trim();
    if (!who) return;
    state.acl.entries.push({ type, who, perms: { ...newBits } });
    state.setfaclLog.unshift(`setfacl -m ${type}:${who}:${permStr(newBits)} ${state.filename}`);
    trim();
    render();
  };
}

function applyBitToggle(info, bit) {
  if (info.type === 'base') {
    const was = state.acl.basePerms[info.scope][bit];
    state.acl.basePerms[info.scope][bit] = was ? 0 : 1;
    const octal = BITS.reduce((n, b) => n + (state.acl.basePerms[info.scope][b] ? (b === 'r' ? 4 : b === 'w' ? 2 : 1) : 0), 0);
    const label = info.scope === 'u' ? 'u' : info.scope === 'g' ? 'g' : 'o';
    state.setfaclLog.unshift(`setfacl -m ${label}::${permStr(state.acl.basePerms[info.scope])} ${state.filename}`);
  } else {
    const e = state.acl.entries[info.idx];
    const was = e.perms[bit];
    e.perms[bit] = was ? 0 : 1;
    state.setfaclLog.unshift(`setfacl -m ${e.type}:${e.who}:${permStr(e.perms)} ${state.filename}`);
  }
  trim();
}

function trim() { if (state.setfaclLog.length > 8) state.setfaclLog.length = 8; }

// --- Challenge mode ---
function renderChallenge(app) {
  const ch = state.ch;
  if (ch.idx >= ch.rounds.length) {
    app.innerHTML = `
      <div class="panel" style="text-align:center;">
        <h2 style="margin:0 0 8px;">Shift over!</h2>
        <p style="color:var(--muted);">Final score: <b style="color:var(--accent);font-size:20px;">${ch.score}</b> / ${ch.rounds.length}</p>
        <button class="next-btn" id="restart">Play again</button>
      </div>
    `;
    document.getElementById('restart').onclick = () => { state.ch = { idx:0, score:0, rounds: buildRounds(), picked:null, revealed:false }; render(); };
    return;
  }
  const round = ch.rounds[ch.idx];
  const guest = GUESTS.find(g => g.id === round.guest);
  const stages = evaluate(round.setup, guest, round.action);
  const verdict = finalVerdict(stages);

  const wrap = document.createElement('div');
  wrap.className = 'club-wrap';

  const left = document.createElement('div');
  left.className = 'acl-list';
  left.innerHTML = `
    <h3>${round.title}</h3>
    <div class="sub">ACL snapshot — no editing, just read it.</div>
    ${renderReadonlyAcl(round.setup)}
    <div class="scoreline">Score: <b>${ch.score}</b> · Round <b>${ch.idx + 1}</b> / ${ch.rounds.length}</div>
  `;

  const right = document.createElement('div');
  right.className = 'panel club-scene';
  right.innerHTML = `
    <div class="bouncer">🕴️</div>
    <div style="font-size:13px;color:var(--muted);margin-top:8px;">
      <b style="color:var(--ink);">${guest.name}</b> (${guest.role}) wants to <b style="color:var(--accent);">${round.action}</b>
    </div>

    <div class="predict-row">
      <button class="allow ${ch.picked === 'allow' ? 'picked' : ''}" data-pick="allow" ${ch.revealed ? 'disabled' : ''}>ALLOW ✓</button>
      <button class="deny ${ch.picked === 'deny' ? 'picked' : ''}" data-pick="deny" ${ch.revealed ? 'disabled' : ''}>DENY ✗</button>
    </div>

    ${ch.revealed ? `
      <div class="verdict-banner ${verdict}">
        Bouncer says: ${verdict === 'allow' ? 'ALLOW ✓' : 'DENY ✗'} — you picked ${ch.picked.toUpperCase()}
        ${ch.picked === verdict ? ' ✓' : ' ✗'}
      </div>
      <div style="text-align:left;color:var(--muted);font-size:12px;margin-bottom:10px;">💡 ${round.teach}</div>
      <div class="stages">
        ${stages.map(s => `
          <div class="stage ${s.skipped ? 'skipped' : ''} ${s.matched && !s.skipped ? 'matched' : ''}">
            <div class="num">${s.num}</div>
            <div>
              <div class="label">${s.label}</div>
              <div class="desc" style="margin-top:2px;">${s.reason}</div>
            </div>
            <div class="verdict ${s.verdict || ''}">${s.matched && !s.skipped ? (s.verdict === 'allow' ? '✓' : '✗') : ''}</div>
          </div>
        `).join('')}
      </div>
      <button class="next-btn" id="next-round">${ch.idx + 1 === ch.rounds.length ? 'See final score →' : 'Next round →'}</button>
    ` : `
      <div style="color:var(--muted);font-size:12px;margin-top:10px;">Predict what the bouncer will say, then reveal the walkthrough.</div>
    `}
  `;

  wrap.appendChild(left);
  wrap.appendChild(right);
  app.appendChild(wrap);

  document.querySelectorAll('[data-pick]').forEach(b => {
    b.onclick = () => {
      ch.picked = b.dataset.pick;
      ch.revealed = true;
      if (ch.picked === verdict) ch.score += 1;
      render();
    };
  });
  const nextBtn = document.getElementById('next-round');
  if (nextBtn) nextBtn.onclick = () => { ch.idx += 1; ch.picked = null; ch.revealed = false; render(); };
}

function renderReadonlyAcl(acl) {
  const row = (tag, who, perms, dashed) => `
    <div class="acl-row ${dashed ? 'mask' : 'effective'}">
      <span class="tag">${tag}</span>
      <span class="who">${who}</span>
      <div class="perm-toggles">
        ${BITS.map(b => `<span class="bit ${perms[b] ? 'on' : ''}" style="cursor:default;">${perms[b] ? b : '-'}</span>`).join('')}
      </div>
      <span></span>
    </div>
  `;
  const parts = [row('user::', acl.owner + ' (owner)', acl.basePerms.u)];
  acl.entries.filter(e => e.type === 'user').forEach(e => parts.push(row('user:', e.who, e.perms)));
  parts.push(row('group::', acl.ownerGroup, acl.basePerms.g));
  acl.entries.filter(e => e.type === 'group').forEach(e => parts.push(row('group:', e.who, e.perms)));
  parts.push(row('mask::', 'caps group & named entries', acl.mask, true));
  parts.push(row('other::', 'everyone else', acl.basePerms.o));
  return parts.join('');
}

// --- Boot ---
document.querySelectorAll('.tab').forEach(t => {
  if (t.dataset && t.dataset.mode) {
    t.onclick = () => { state.mode = t.dataset.mode; render(); };
  }
});

render();
