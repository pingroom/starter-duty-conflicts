import { createHash } from 'node:crypto';

export const TTL = 900;
export const CLOCK_SKEW_MS = 60000;
export const TOKEN = /^[^\s\x00-\x1f\x7f]{1,8192}(?![\s\S])/;
export const ROOM = /^[A-Z0-9]{12}$(?![\s\S])/;
export const isId = (value) => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/.test(value);
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value, expected) => {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort(), wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
};
const word = (value) => typeof value === 'string' && /^[a-z][a-z0-9_-]{0,39}$(?![\s\S])/.test(value);
const line = (value, max) => typeof value === 'string' && value.length > 0 && value.length <= max && value.isWellFormed()
  && !/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(value) && value.trim() === value;
const canonical = (value) => Array.isArray(value) ? value.map(canonical) : record(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value;
export const hash = (value) => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');

export function iso(raw) {
  if (typeof raw !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$(?![\s\S])/.test(raw)) throw new Error('Expected a UTC timestamp.');
  const time = Date.parse(raw);
  if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== raw.slice(0, 19)) throw new Error('Invalid UTC timestamp.');
  return new Date(time).toISOString();
}


const safeId = value => word(value) && value.length <= 12 && !['constructor', 'prototype', '__proto__'].includes(value);
const order = (a, b) => a < b ? -1 : a > b ? 1 : 0;
export const POLICY = Object.freeze({ name: 'positive-grant-duty-pairs-v1', inheritance: 'a role includes all grants reachable through its inherits edges', cycles: 'bounded set closure; not provider conformance', witnesses: 'shortest role path; lexicographic role-ID path breaks ties', scope: 'supplied action pairs and frozen subject assignments only', unknown: 'withhold complete analysis', execution: 'local diagnostic; no access changes' });
export const POLICY_HASH = hash(POLICY);
const promptFor = (input, pair) => {
  const labels = pair.actions.map(id => input.actions.find(action => action.id === id));
  return `${input.title}\n${input.context}\nPair ${pair.id}: ${labels.map(action => `${action.id}: ${action.label}`).join(' + ')}\nMay ONE subject possess BOTH actions in this snapshot? Incompatible prohibits their combination. Allowed permits this pair only. Unknown withholds the complete diagnostic. No access is changed.`;
};
const bounded = (value, maximum) => Array.isArray(value) && value.length <= maximum;
function references(values, known, label) {
  if (!bounded(values, known.size) || new Set(values).size !== values.length || Array.from(values).some(id => !known.has(id))) throw new Error(`${label} must be distinct declared IDs.`);
  return [...values].sort(order);
}
export function validateInput(input) {
  if (!keys(input, ['auditId', 'title', 'context', 'actions', 'roles', 'subjects', 'pairs']) || !word(input.auditId) || input.auditId.length > 32 || !line(input.title, 40) || !line(input.context, 80)
    || !bounded(input.actions, 12) || input.actions.length < 2 || !bounded(input.roles, 12) || !input.roles.length || !bounded(input.subjects, 12) || !input.subjects.length || !bounded(input.pairs, 8) || !input.pairs.length) throw new Error('Supply audit metadata, 2–12 actions, 1–12 roles, 1–12 subjects and 1–8 candidate action pairs.');
  const named = (values, expected, label) => {
    const ids = new Set();
    for (const value of Array.from(values)) {
      if (!keys(value, expected) || !safeId(value.id) || ids.has(value.id) || !line(value.label, 32)) throw new Error(`${label} need unique safe IDs, short labels and exact fields.`);
      ids.add(value.id);
    }
    return ids;
  };
  const actionIds = named(input.actions, ['id', 'label'], 'Actions');
  const roleIds = named(input.roles, ['id', 'label', 'inherits', 'grants'], 'Roles');
  named(input.subjects, ['id', 'label', 'roles'], 'Subjects');
  const actions = input.actions.map(value => ({ ...value })).sort((a, b) => order(a.id, b.id));
  const roles = input.roles.map(role => ({ id: role.id, label: role.label, inherits: references(role.inherits, roleIds, 'Inherited roles'), grants: references(role.grants, actionIds, 'Granted actions') })).sort((a, b) => order(a.id, b.id));
  const subjects = input.subjects.map(subject => ({ id: subject.id, label: subject.label, roles: references(subject.roles, roleIds, 'Assigned roles') })).sort((a, b) => order(a.id, b.id));
  const pairIds = new Set(), combinations = new Set();
  const pairs = Array.from(input.pairs, pair => {
    if (!keys(pair, ['id', 'actions']) || !safeId(pair.id) || pairIds.has(pair.id) || !Array.isArray(pair.actions) || pair.actions.length !== 2) throw new Error('Pairs need unique safe IDs and exactly two distinct declared actions.');
    const actions = references(pair.actions, actionIds, 'Pair actions'), combination = actions.join(':');
    if (combinations.has(combination)) throw new Error('Each unordered action pair may be declared only once.');
    pairIds.add(pair.id); combinations.add(combination); return { id: pair.id, actions };
  }).sort((a, b) => order(a.id, b.id));
  const result = { auditId: input.auditId, title: input.title, context: input.context, actions, roles, subjects, pairs };
  if (pairs.some(pair => promptFor(result, pair).length > 500)) throw new Error('Pair policy prompt exceeds 500 UTF-16 units.');
  return result;
}
export function validateConfig(config) {
  if (!keys(config, ['participant']) || !keys(config.participant, ['id', 'label']) || !isId(config.participant.id) || !line(config.participant.label, 60)) throw new Error('Config requires an exact policy owner UUID and label.');
  return structuredClone(config);
}
export const itemsFor = input => validateInput(input).pairs;
export function requestFor(rawInput, config, itemId, attemptId) {
  const input = validateInput(rawInput); validateConfig(config); const pair = input.pairs.find(pair => pair.id === itemId);
  if (!pair || !isId(attemptId)) throw new Error('Invalid action pair or attempt.');
  const key = `duties-${attemptId}`;
  return { prompt: promptFor(input, pair), context: `To ${config.participant.id}`,
    options: [{ value: 'incompatible', label: 'Incompatible', style: 'default' }, { value: 'allowed', label: 'Allowed', style: 'default' }, { value: 'unknown', label: 'Unknown', style: 'default' }],
    responder_scope: 'direct', target_user_id: config.participant.id, ttl: TTL, correlation_id: key,
    data: { input_hash: hash(input), pair_hash: hash(pair), policy_hash: POLICY_HASH, item_id: pair.id, attempt_id: attemptId }, idempotencyKey: key };
}

/** Pure positive-grant closure; CLI exports additionally require attributed policy evidence. */
export function analyzeDuties(rawInput, selections) {
  const input = validateInput(rawInput), ids = input.pairs.map(pair => pair.id);
  if (!keys(selections, ids) || ids.some(id => !['incompatible', 'allowed'].includes(selections[id]))) throw new Error('Every candidate pair needs exactly one known Incompatible or Allowed policy.');
  const roles = new Map(input.roles.map(role => [role.id, role]));
  const subjects = input.subjects.map(subject => {
    const paths = new Map(subject.roles.map(roleId => [roleId, [roleId]])), queue = [...subject.roles], witnesses = new Map();
    for (let cursor = 0; cursor < queue.length; cursor++) {
      const role = roles.get(queue[cursor]), path = paths.get(role.id);
      for (const actionId of role.grants) if (!witnesses.has(actionId)) witnesses.set(actionId, { actionId, rolePath: [...path] });
      for (const inherited of role.inherits) if (!paths.has(inherited)) { paths.set(inherited, [...path, inherited]); queue.push(inherited); }
    }
    return { subjectId: subject.id, assignedRoleIds: [...subject.roles], effectiveRoleIds: [...paths.keys()].sort(order), effectiveActionIds: [...witnesses.keys()].sort(order), witnesses: [...witnesses.values()].sort((a, b) => order(a.actionId, b.actionId)) };
  });
  const violations = input.pairs.flatMap(pair => selections[pair.id] !== 'incompatible' ? [] : subjects.flatMap(subject => pair.actions.every(action => subject.effectiveActionIds.includes(action)) ? [{ subjectId: subject.subjectId, pairId: pair.id, actionIds: [...pair.actions], witnesses: pair.actions.map(action => structuredClone(subject.witnesses.find(witness => witness.actionId === action))) }] : []));
  const pairs = input.pairs.map(pair => ({ ...pair, classification: selections[pair.id], violatingSubjectIds: violations.filter(row => row.pairId === pair.id).map(row => row.subjectId) }));
  const declared = new Set(input.pairs.map(pair => pair.actions.join(':')));
  const unassessedActionPairs = input.actions.flatMap((left, index) => input.actions.slice(index + 1).flatMap(right => declared.has(`${left.id}:${right.id}`) ? [] : [[left.id, right.id]]));
  return { hasConflicts: violations.length > 0, subjects, pairs, violations,
    coverage: { declaredPairCount: pairs.length, possiblePairCount: input.actions.length * (input.actions.length - 1) / 2, unassessedActionPairs },
    sourceHash: hash(input), policyHash: POLICY_HASH, accessChanged: false, livePermissionsVerified: false, complianceCertified: false };
}
export function dutyAudit(rawInput, answers) {
  const input = validateInput(rawInput);
  if (!Array.isArray(answers) || answers.length !== input.pairs.length || Array.from(answers).some((row, index) => !keys(row, ['pairId', 'choice']) || row.pairId !== input.pairs[index].id || ![null, 'incompatible', 'allowed', 'unknown'].includes(row.choice))) throw new Error('Supply one ordered Incompatible, Allowed, Unknown or null choice per pair.');
  const missingPairIds = answers.filter(row => row.choice === null).map(row => row.pairId), unknownPairIds = answers.filter(row => row.choice === 'unknown').map(row => row.pairId);
  const status = missingPairIds.length ? 'incomplete' : unknownPairIds.length ? 'unknown' : 'complete';
  return { status, missingPairIds, unknownPairIds, analysis: status === 'complete' ? analyzeDuties(input, Object.fromEntries(answers.map(row => [row.pairId, row.choice]))) : null };
}

export function validateState(state, rawInput) {
  const input = validateInput(rawInput);
  if (!keys(state, ['version', 'inputHash', 'config', 'room', 'credentialHash', 'startedAt', 'attempts']) || state.version !== 1
    || state.inputHash !== hash(input) || typeof state.room !== 'string' || !ROOM.test(state.room)
    || typeof state.credentialHash !== 'string' || !/^[0-9a-f]{64}$(?![\s\S])/.test(state.credentialHash)
    || !Array.isArray(state.attempts) || state.attempts.length > itemsFor(input).length || iso(state.startedAt) !== state.startedAt) throw new Error('Invalid state or changed grant snapshot. Restore the original input and configuration.');
  validateConfig(state.config);
  const items = itemsFor(input), ids = new Set(), questionIds = new Set(); let previous = state.startedAt, askerId;
  for (const [index, attempt] of state.attempts.entries()) {
    if (!keys(attempt, ['id', 'itemId', 'createdAt', 'request', 'questionId', 'status', 'observation']) || !isId(attempt.id) || ids.has(attempt.id)
      || attempt.itemId !== items[index].id || iso(attempt.createdAt) !== attempt.createdAt || attempt.createdAt < previous
      || hash(attempt.request) !== hash(requestFor(input, state.config, attempt.itemId, attempt.id))
      || !['creating', 'pending', 'answered', 'expired', 'cancelled', 'invalid_answer'].includes(attempt.status)) throw new Error('Invalid saved pair classification or order.');
    ids.add(attempt.id); previous = attempt.createdAt;
    if (attempt.status === 'creating') {
      if (attempt.questionId !== null || attempt.observation !== null) throw new Error('Invalid uncertain creation state.');
    } else {
      if (!isId(attempt.questionId) || questionIds.has(attempt.questionId)) throw new Error('Invalid or repeated Question ID.');
      questionIds.add(attempt.questionId); validateObservation(attempt.observation, attempt.status, attempt.request);
      if (attempt.observation.checkedAt < attempt.createdAt) throw new Error('Observation predates its saved creation intent.');
      previous = attempt.observation.checkedAt;
      if (Date.parse(attempt.observation.createdAt) < Date.parse(attempt.createdAt) - CLOCK_SKEW_MS) throw new Error('Question predates its saved creation intent.');
      if (askerId !== undefined && attempt.observation.askerId !== askerId) throw new Error('Questions belong to different asking registrations.');
      askerId = attempt.observation.askerId;
    }
    if (['creating', 'pending'].includes(attempt.status) && index !== state.attempts.length - 1) throw new Error('Only the last confirmation may have an active Question.');
  }
  return state;
}



export function report(state, rawInput) {
  const input = validateInput(rawInput); validateState(state, input);
  const answers = input.pairs.map(pair => {
    const attempt = state.attempts.find(row => row.itemId === pair.id), answer = attempt?.observation?.answer;
    return { pairId: pair.id, status: attempt?.status === 'creating' ? 'create_unknown' : attempt?.status ?? 'unasked',
      choice: answer?.value ?? null, label: answer?.label ?? null, questionId: attempt?.questionId ?? null, attemptId: attempt?.id ?? null,
      responderId: answer?.responderId ?? null, answeredAt: answer?.answeredAt ?? null, askerId: attempt?.observation?.askerId ?? null, observedAt: attempt?.observation?.checkedAt ?? null };
  });
  const calculation = dutyAudit(input, answers.map(({ pairId, choice }) => ({ pairId, choice })));
  const active = answers.find(row => ['create_unknown', 'pending'].includes(row.status));
  const status = active?.status ?? (answers.some(row => row.status === 'unasked') ? 'ready' : calculation.status);
  return { version: 1, auditId: input.auditId, sourceHash: hash(input), source: input, policy: POLICY, policyHash: POLICY_HASH,
    participant: state.config.participant, room: state.room, configHash: hash(state.config), answers, ...calculation, status };
}


function validateObservation(observation, status, request) {
  if (!keys(observation, ['createdAt', 'expiresAt', 'checkedAt', 'askerId', 'resolvedAt', 'answer']) || !isId(observation.askerId)) throw new Error('Invalid saved observation.');
  for (const key of ['createdAt', 'expiresAt', 'checkedAt']) if (iso(observation[key]) !== observation[key]) throw new Error('Invalid saved timestamp.');
  const duration = Date.parse(observation.expiresAt) - Date.parse(observation.createdAt);
  if (duration < TTL * 1000 - 1000 || duration > TTL * 1000 + 1000) throw new Error('Question lifetime differs from the saved request.');
  const latest = Date.parse(observation.checkedAt) + CLOCK_SKEW_MS;
  if (Date.parse(observation.createdAt) > latest) throw new Error('Question creation is implausibly in the future. Check the local clock.');
  if (status === 'pending') {
    if (observation.resolvedAt !== null) throw new Error('Pending Question has a resolution timestamp.');
  } else if (iso(observation.resolvedAt) !== observation.resolvedAt || observation.resolvedAt < observation.createdAt
    || Date.parse(observation.resolvedAt) > latest
    || (status === 'expired' ? observation.resolvedAt < observation.expiresAt : observation.resolvedAt > observation.expiresAt)) throw new Error('Invalid Question resolution time.');
  if (status === 'answered') {
    const answer = observation.answer;
    if (!keys(answer, ['value', 'label', 'responderId', 'answeredAt']) || answer.responderId !== request.target_user_id
      || !request.options.some((option) => option.value === answer.value && option.label === answer.label)
      || iso(answer.answeredAt) !== answer.answeredAt || answer.answeredAt !== observation.resolvedAt
      || answer.answeredAt < observation.createdAt || answer.answeredAt > observation.expiresAt) throw new Error('Invalid saved pair classification evidence.');
  } else if (observation.answer !== null) throw new Error('Unanswered pair classifications must not contain pair classification evidence.');
}

export function observeQuestion(q, request, questionId, room, checkedAt) {
  if (!isId(questionId) || q?.id !== questionId || q.kind !== 'question' || (q.is_handoff !== undefined && q.is_handoff !== false)
    || q.asker?.type !== 'agent' || !isId(q.asker?.id) || q.prompt !== request.prompt || q.context !== request.context
    || q.responder_scope !== 'direct' || q.target_user_id !== request.target_user_id || q.resolution_policy !== 'first'
    || (q.results !== undefined && q.results !== null) || q.text_input !== null || q.correlation_id !== request.correlation_id || q.reply_to !== null || hash(q.data) !== hash(request.data)
    || (q.room_code ?? q.room?.code) !== room || q.room_code !== undefined && q.room_code !== room
    || q.room !== undefined && q.room?.code !== room || !['pending', 'answered', 'expired', 'cancelled'].includes(q.state)
    || !Array.isArray(q.options) || q.options.length !== request.options.length
    || Array.from(q.options).some((option, index) => option?.value !== request.options[index].value || option?.label !== request.options[index].label
      || (option?.primary !== undefined && option.primary !== false) || (option?.destructive !== undefined && option.destructive !== false))) throw new Error('Question does not match the saved configuration, room, or reviewer.');
  const observation = { createdAt: iso(q.created_at), expiresAt: iso(q.expires_at), checkedAt: iso(checkedAt), askerId: q.asker.id,
    resolvedAt: q.resolved_at === null ? null : iso(q.resolved_at), answer: null };
  let status = q.state === 'answered' ? 'invalid_answer' : q.state;
  if (q.state !== 'answered' && q.answer !== null) throw new Error('Unresolved Question includes an unexpected answer.');
  if (q.state === 'answered') {
    const answer = q.answer;
    try {
      if (!answer || answer.text !== null || answer.responder?.id !== request.target_user_id
        || !request.options.some((option) => option.value === answer.value && option.label === answer.label)) throw new Error('Invalid answer.');
      observation.answer = { value: answer.value, label: answer.label, responderId: answer.responder.id, answeredAt: iso(answer.answered_at) };
      validateObservation(observation, 'answered', request); status = 'answered';
    } catch { observation.answer = null; }
  }
  validateObservation(observation, status, request);
  return { status, observation };
}

export function assertParticipantRoom(rooms, room, participantId) {
  if (!Array.isArray(rooms) || rooms.length > 1000) throw new Error('Invalid room inventory.');
  const matches = rooms.filter((item) => item?.invite_code === room), selected = matches[0];
  if (matches.length !== 1 || selected.type !== 'standard' || selected.is_public !== false || !Array.isArray(selected.members)
    || selected.members.length > 1000 || !selected.members.some((member) => member?.user_id === participantId)) throw new Error('Use a granted standard private room containing the named participant.');
}
