import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeDuties, dutyAudit, validateInput, hash, requestFor, itemsFor, POLICY_HASH } from '../src/model.js';
import { step, exportAnalysis } from '../src/engine.js';
import { mockApi, CONFIG, ROOM_CODE, id } from '../src/mock.js';

const fixture = JSON.parse(await readFile(new URL('../examples/grants.json', import.meta.url), 'utf8'));
const example = () => structuredClone(fixture);
const selections = (input, value = 'incompatible') => Object.fromEntries(input.pairs.map(pair => [pair.id, value]));
const rows = (input, values) => validateInput(input).pairs.map((pair, index) => ({ pairId: pair.id, choice: values[index] }));

// Independent repeated-set union oracle, with no path search or production closure helpers.
function fixedPoint(input, assigned) {
  const reachable = new Set(assigned);
  let changed = true;
  while (changed) {
    changed = false;
    for (const role of input.roles) if (reachable.has(role.id)) for (const target of role.inherits) if (!reachable.has(target)) { reachable.add(target); changed = true; }
  }
  const actions = new Set(input.roles.filter(role => reachable.has(role.id)).flatMap(role => role.grants));
  return { roles: [...reachable].sort(), actions: [...actions].sort() };
}
function verifyWitnesses(input, subject) {
  const assigned = input.subjects.find(row => row.id === subject.subjectId).roles;
  for (const witness of subject.witnesses) {
    assert.ok(assigned.includes(witness.rolePath[0]));
    assert.equal(new Set(witness.rolePath).size, witness.rolePath.length);
    for (let i = 1; i < witness.rolePath.length; i++) assert.ok(input.roles.find(role => role.id === witness.rolePath[i - 1]).inherits.includes(witness.rolePath[i]));
    assert.ok(input.roles.find(role => role.id === witness.rolePath.at(-1)).grants.includes(witness.actionId));
    const candidates = [];
    const enumerate = path => {
      const role = input.roles.find(row => row.id === path.at(-1));
      if (role.grants.includes(witness.actionId)) candidates.push(path);
      for (const next of role.inherits) if (!path.includes(next)) enumerate([...path, next]);
    };
    for (const root of assigned) enumerate([root]);
    candidates.sort((a, b) => a.length - b.length || (a.join(':') < b.join(':') ? -1 : a.join(':') > b.join(':') ? 1 : 0));
    assert.deepEqual(witness.rolePath, candidates[0]);
  }
}

test('all 512 directed three-role graphs and 8 assignment sets agree with independent fixed-point closure', () => {
  for (let graph = 0; graph < 512; graph++) for (let assigned = 0; assigned < 8; assigned++) {
    const input = { auditId: 'graph', title: 'Graph closure', context: 'Harmless declared grants.', actions: [{ id: 'a', label: 'A' }, { id: 'b', label: 'B' }, { id: 'c', label: 'C' }],
      roles: ['r0', 'r1', 'r2'].map((id, i) => ({ id, label: id, grants: ['a', 'b', 'c'].slice(i, i + 1), inherits: ['r0', 'r1', 'r2'].filter((_, j) => graph & (1 << (i * 3 + j))) })),
      subjects: [{ id: 's', label: 'Subject', roles: ['r0', 'r1', 'r2'].filter((_, i) => assigned & (1 << i)) }], pairs: [{ id: 'ab', actions: ['a', 'b'] }] };
    const result = analyzeDuties(input, { ab: 'incompatible' }), subject = result.subjects[0], expected = fixedPoint(input, input.subjects[0].roles);
    assert.deepEqual(subject.effectiveRoleIds, expected.roles); assert.deepEqual(subject.effectiveActionIds, expected.actions);
    assert.equal(result.hasConflicts, expected.actions.includes('a') && expected.actions.includes('b'));
    verifyWitnesses(input, subject);
  }
});

test('inherited and separately assigned capabilities produce same-subject conflict witnesses', () => {
  const input = example(), result = analyzeDuties(input, selections(input));
  assert.equal(result.violations.length, 1); assert.equal(result.violations[0].subjectId, 'alex');
  assert.deepEqual(result.violations[0].witnesses, [{ actionId: 'prepare', rolePath: ['editor', 'writer'] }, { actionId: 'publish', rolePath: ['editor', 'publisher'] }]);
  input.subjects[0].roles = ['publisher', 'writer'];
  assert.deepEqual(analyzeDuties(input, selections(input)).violations[0].witnesses.map(row => row.rolePath), [['writer'], ['publisher']]);
});

test('shortest witnesses prefer direct grants and stable role IDs across diamond paths', () => {
  const input = example();
  input.roles.push({ id: 'alt', label: 'Alternative', inherits: ['writer'], grants: [] });
  input.roles.find(role => role.id === 'editor').inherits.push('alt');
  let result = analyzeDuties(input, selections(input));
  assert.deepEqual(result.subjects[0].witnesses.find(row => row.actionId === 'prepare').rolePath, ['editor', 'writer']);
  input.subjects[0].roles = ['writer', 'editor'];
  result = analyzeDuties(input, selections(input));
  assert.deepEqual(result.subjects[0].witnesses.find(row => row.actionId === 'prepare').rolePath, ['writer']);
  input.subjects[0].roles = ['editor', 'alt'];
  result = analyzeDuties(input, selections(input));
  assert.deepEqual(result.subjects[0].witnesses.find(row => row.actionId === 'prepare').rolePath, ['alt', 'writer']);
});

test('self edges and inheritance cycles terminate without duplicate grants or paths', () => {
  const input = example(); input.roles.find(role => role.id === 'writer').inherits = ['writer', 'editor'];
  const result = analyzeDuties(input, selections(input));
  for (const subject of result.subjects) { verifyWitnesses(input, subject); assert.equal(new Set(subject.effectiveActionIds).size, subject.effectiveActionIds.length); }
  assert.deepEqual(result.violations.map(row => [row.subjectId, row.pairId]), [['alex', 'prepare_pub'], ['sam', 'prepare_pub'], ['sam', 'publish_ret']]);
});

test('disconnected roles and different subjects never combine into one conflict', () => {
  const input = example(); input.subjects[0].roles = ['publisher']; input.subjects[1].roles = ['writer'];
  const result = analyzeDuties(input, selections(input));
  assert.equal(result.hasConflicts, false); assert.deepEqual(result.violations, []);
  input.subjects[0].roles = [];
  assert.deepEqual(analyzeDuties(input, selections(input)).subjects[0].effectiveActionIds, []);
});

test('Allowed permits only the candidate pair and unassessed combinations remain explicit', () => {
  const input = example(), result = analyzeDuties(input, selections(input, 'allowed'));
  assert.equal(result.hasConflicts, false);
  assert.deepEqual(result.coverage, { declaredPairCount: 2, possiblePairCount: 3, unassessedActionPairs: [['prepare', 'retire']] });
  assert.equal(result.accessChanged, false); assert.equal(result.livePermissionsVerified, false); assert.equal(result.complianceCertified, false);
});

test('Unknown and missing policy responses withhold complete analysis and preserve their IDs', () => {
  const input = example();
  assert.deepEqual(dutyAudit(input, rows(input, ['incompatible', 'unknown'])), { status: 'unknown', missingPairIds: [], unknownPairIds: ['publish_ret'], analysis: null });
  assert.equal(dutyAudit(input, rows(input, [null, 'unknown'])).status, 'incomplete');
  assert.equal(dutyAudit(input, rows(input, ['allowed', 'allowed'])).status, 'complete');
  for (const bad of [{}, { prepare_pub: 'incompatible' }, { ...selections(input), extra: 'allowed' }, selections(input, 'unknown')]) assert.throws(() => analyzeDuties(input, bad));
  assert.throws(() => dutyAudit(input, rows(input, ['allowed', 'incompatible']).reverse()));
});

test('canonical sets ignore array and pair orientation order; content edits change identity', () => {
  const input = example(), shuffled = example();
  for (const field of ['actions', 'roles', 'subjects', 'pairs']) shuffled[field].reverse();
  for (const role of shuffled.roles) { role.inherits.reverse(); role.grants.reverse(); }
  for (const subject of shuffled.subjects) subject.roles.reverse();
  for (const pair of shuffled.pairs) pair.actions.reverse();
  assert.deepEqual(validateInput(input), validateInput(shuffled)); assert.deepEqual(analyzeDuties(input, selections(input)), analyzeDuties(shuffled, selections(shuffled)));
  shuffled.subjects[0].roles = []; assert.notEqual(hash(validateInput(input)), hash(validateInput(shuffled)));
});

test('bad references, duplicate sets, duplicate unordered pairs and unsupported semantics fail', () => {
  const mutations = [
    x => { x.roles[0].inherits.push('missing'); }, x => { x.roles[0].grants = ['missing']; }, x => { x.subjects[0].roles = ['missing']; },
    x => { x.roles[0].inherits.push(x.roles[0].inherits[0]); }, x => { x.roles[1].grants.push(x.roles[1].grants[0]); }, x => { x.subjects[0].roles.push(x.subjects[0].roles[0]); },
    x => { x.pairs[0].actions = ['prepare', 'prepare']; }, x => { x.pairs[0].actions = ['prepare', 'missing']; },
    x => { x.pairs.push({ id: 'duplicate', actions: [...x.pairs[0].actions].reverse() }); }, x => { x.pairs[1].id = x.pairs[0].id; },
    x => { x.roles[0].deny = ['prepare']; }, x => { x.subjects[0].session = 'active'; }, x => { x.actions[0].scope = '*'; },
    x => { x.roles[0].id = '__proto__'; }, x => { x.title += '\n'; }, x => { x.context = '\ud800'; }, x => { x.subjects[0].label += '\u200b'; },
    x => { x.actions[0] = null; }, x => { x.pairs[0] = null; }, x => { delete x.roles[0]; }, x => { x.subjects = []; }, x => { x.pairs = []; },
  ];
  for (const mutate of mutations) { const input = example(); mutate(input); assert.throws(() => validateInput(input)); }
});

test('Questions expose candidate policy context and labels without subject or role records', () => {
  const input = example(), request = requestFor(input, CONFIG, 'prepare_pub', id(1));
  assert.ok(request.prompt.length <= 500); assert.equal(request.data.policy_hash, POLICY_HASH);
  assert.equal(request.target_user_id, CONFIG.participant.id); assert.equal(request.responder_scope, 'direct');
  for (const secret of ['Alex (fictional)', 'Sam (fictional)', 'Listing editor', 'Card writer']) assert.ok(!JSON.stringify(request).includes(secret));
  assert.deepEqual(itemsFor(input).map(row => row.id), ['prepare_pub', 'publish_ret']);
});

test('maximum bounded snapshot fits eight Questions and private complete export', async t => {
  const input = { auditId: 'maximum', title: 'Maximum fixture', context: 'Declared grant-combination policy.', actions: Array.from({ length: 12 }, (_, i) => ({ id: `a${i}`, label: `Action ${i}` })), roles: [], subjects: [], pairs: [] };
  input.roles = Array.from({ length: 12 }, (_, i) => ({ id: `r${i}`, label: `Role ${i}`, inherits: Array.from({ length: 12 }, (_, j) => `r${j}`), grants: input.actions.map(row => row.id) }));
  input.subjects = Array.from({ length: 12 }, (_, i) => ({ id: `s${i}`, label: `Subject ${i}`, roles: input.roles.map(row => row.id) }));
  input.pairs = Array.from({ length: 8 }, (_, i) => ({ id: `p${i}`, actions: ['a0', `a${i + 1}`] }));
  const directory = await mkdtemp(join(tmpdir(), 'duties-maximum-')); t.after(() => rm(directory, { recursive: true, force: true }));
  const now = () => '2026-01-01T09:00:00.000Z', api = mockApi(now), options = { client: api.client, directory, input, config: CONFIG, token: 'fixture', room: ROOM_CODE, now };
  for (let i = 0; i < 8; i++) { const pending = await step(options); api.answer(pending.answers.find(row => row.status === 'pending').questionId, 'incompatible'); await step(options); }
  const result = await exportAnalysis(directory, input); assert.equal(result.analysis.violations.length, 96);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < 1024 * 1024); assert.equal((await stat(join(directory, 'analysis.json'))).mode & 0o777, 0o600);
  assert.equal(api.calls.filter(call => call.method === 'POST').length, 8);
});
