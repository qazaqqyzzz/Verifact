const {test} = require('node:test');
const assert = require('node:assert/strict');
const {visitor} = require('../verifact/static/report_view.js');
const now = Date.parse('2026-10-31T00:00:00Z');
const expired = '2026-10-30T23:59:59Z';
const future = '2026-10-31T00:05:00Z';
function report(reasons, status = 'warning') {
  return {visitor_assessment: {status, tone: status === 'no_warning' ? 'green' : 'red', label:'Recorded result',
    reasons, expires_at:expired, coverage:{connection:'assessed',community_feed:'no_match'}},
    community_reputation:{status:'no_match',expires_at:expired}};
}
test('a stale clean list cannot remain a green current verdict', () => {
  const value = report([{id:'community_no_match',source:'community'}], 'no_warning');
  assert.equal(visitor(value, now).status, 'unknown');
  assert.equal(visitor(value, now).coverage.community_feed, 'unavailable');
  assert.ok(!visitor(value, now).reasons.some(r => r.id === 'community_no_match'));
  assert.equal(value.visitor_assessment.status, 'no_warning');
});
test('expiry does not erase recorded HTTP and password-form warnings', () => {
  for (const id of ['unencrypted_destination','unsafe_password_form','downgrade','certificate_verification']) {
    const value = report([{id,source:'page'}, {id:'community_match',source:'community'}]);
    assert.equal(visitor(value, now).status, 'warning');
    assert.equal(visitor(value, now).reasons[0].id, id);
    assert.ok(!visitor(value, now).reasons.some(r => r.id === 'community_match'));
  }
});
test('a current provider warning survives expiry of the other provider', () => {
  const value = report([{id:'known_threat',source:'reputation'}]);
  value.reputation = {status:'listed', expires_at:future};
  assert.equal(visitor(value, now).status, 'warning');
  assert.equal(visitor(value, now).reasons[0].id, 'known_threat');
});
test('an expired provider-only warning becomes incomplete, not safe', () => {
  assert.equal(visitor(report([{id:'community_match',source:'community'}]), now).status, 'unknown');
});
test('a destination mismatch stays caution after list expiry', () => {
  const value = report([{id:'unexpected_destination',source:'link'}], 'caution');
  assert.equal(visitor(value, now).status, 'caution');
  assert.equal(visitor(value, now).reasons[0].id, 'unexpected_destination');
});
test('a fresh result stays unchanged and missing results never pass', () => {
  const value = report([], 'no_warning');
  value.visitor_assessment.expires_at = future;
  assert.equal(visitor(value, now), value.visitor_assessment);
  assert.equal(visitor({}, now).status, 'unknown');
});
