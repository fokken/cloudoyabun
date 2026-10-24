const cases = [];
const test = (name, run) => cases.push({name, run});
const assert = require('assert').strict;
const fs = require('fs');
const vm = require('vm');
const source = fs.readFileSync('cloudoyabun/static/app.js', 'utf8');
const code = source.slice(source.indexOf('async function saveTriage('), source.indexOf('async function loadRuns('));

function setup() {
  const fields = {};
  for (const key of ['disposition', 'category', 'notes', 'severity_override', 'priority', 'report_order', 'tags']) fields[key] = {value: key === 'disposition' ? 'confirmed' : ['priority', 'report_order'].includes(key) ? '0' : ''};
  fields.selected = {checked: false};
  const button = {}, form = {elements: fields, querySelector: () => button};
  let resolve, reject, closed = false;
  const nodes = {'triage-form': form, 'finding-dialog': {close: () => { closed = true; }}, 'save-status': {textContent: ''}};
  const state = {assessment: 'one', detailRequest: 1, finding: {id: 'A', revision: 0}};
  const selection = new Map([['A', {}], ['B', {}]]);
  const context = {state, selection, $: id => nodes[id], jsonOptions: (method, body) => ({method, body}),
    api: () => new Promise((yes, no) => { resolve = yes; reject = no; }), notice() {}, updateSelection() {}, refreshOverview: async () => {}, loadFindings: async () => {}};
  vm.createContext(context); vm.runInContext(code, context);
  const pending = context.saveTriage({preventDefault() {}});
  return {state, selection, pending, button, nodes, resolve: () => resolve({}), reject: () => reject(new Error('Old save failed')), closed: () => closed};
}

test('late save cannot close a different finding or remove its selection', async () => {
  const t = setup(); t.state.finding = {id: 'B', revision: 0}; t.state.detailRequest++;
  t.resolve(); await t.pending;
  assert.equal(t.closed(), false); assert.equal(t.selection.has('B'), true); assert.equal(t.selection.has('A'), false);
});

test('late save error cannot replace feedback for a new dialog', async () => {
  const t = setup(); t.state.finding = {id: 'B', revision: 0}; t.state.detailRequest++;
  t.reject(); await t.pending;
  assert.equal(t.nodes['save-status'].textContent, ''); assert.equal(t.closed(), false);
});

test('switching assessment during save leaves its selection untouched', async () => {
  const t = setup(); t.state.assessment = 'two'; t.state.finding = null;
  t.resolve(); await t.pending;
  assert.equal(t.closed(), false); assert.equal(t.selection.has('A'), true);
});

test('current finding still closes after a successful save', async () => {
  const t = setup(); t.resolve(); await t.pending;
  assert.equal(t.closed(), true); assert.equal(t.selection.has('A'), false); assert.equal(t.button.disabled, false);
});

(async () => {
  for (const {name, run} of cases) { await run(); console.log(`PASS: ${name}`); }
})().catch(error => { console.error(error); process.exitCode = 1; });
