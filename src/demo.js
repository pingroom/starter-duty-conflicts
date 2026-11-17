import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJson } from './storage.js';
import { step, exportAnalysis } from './engine.js';
import { mockApi, CONFIG, ROOM_CODE } from './mock.js';

const input = await readJson(new URL('../examples/grants.json', import.meta.url), 65536);
for (const [scenario, choices] of [
  ['inherited-conflict', ['incompatible', 'incompatible']],
  ['allowed-pairs', ['allowed', 'allowed']],
  ['unknown', ['incompatible', 'unknown']],
]) {
  const directory = await mkdtemp(join(tmpdir(), 'pingroom-duties-demo-'));
  try {
    const now = () => '2026-01-01T09:00:00.000Z', api = mockApi(now);
    const options = { client: api.client, directory, input, config: CONFIG, token: 'offline-fixture-token', room: ROOM_CODE, now };
    let result;
    for (const choice of choices) {
      const pending = await step(options), question = pending.answers.find(answer => answer.status === 'pending');
      api.answer(question.questionId, choice); result = await step(options);
    }
    assert.equal(api.calls.filter(call => call.method === 'POST').length, 2);
    if (scenario === 'unknown') {
      assert.equal(result.status, 'unknown'); assert.equal(result.analysis, null); await assert.rejects(exportAnalysis(directory, input));
    } else {
      assert.equal(result.status, 'complete'); assert.equal(result.analysis.hasConflicts, scenario === 'inherited-conflict');
      await exportAnalysis(directory, input);
    }
    console.log(JSON.stringify({ scenario, transport: 'local mock through the real SDK; no live delivery', status: result.status, analysis: result.analysis, unknownPairIds: result.unknownPairIds }, null, 2));
  } finally { await rm(directory, { recursive: true, force: true }); }
}
