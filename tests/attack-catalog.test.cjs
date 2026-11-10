const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'docs/index.html'), 'utf8');
// Read-only comparison with the pre-v20.1 CSC baseline; no STIX bundle is vendored.
const baseline = execFileSync('git', ['show', '394f211:docs/index.html'], { cwd: root, encoding: 'utf8' });
const tacticMap = {
  reconnaissance: 'reconnaissance', resource_preparation: 'resource-development',
  initial_access: 'initial-access', execution: 'execution', persistence: 'persistence',
  privilege_escalation: 'privilege-escalation', stealth: 'stealth',
  defense_impairment: 'defense-impairment', credential_access: 'credential-access',
  discovery: 'discovery', lateral_movement: 'lateral-movement', data_collection: 'collection',
  management: 'command-and-control', data_exfiltration: 'exfiltration', destructive_impact: 'impact'
};
const addedHours = { T1039: 2, T1578: 4, T1669: 4, T1696: 4, T1697: 2, T1698: 4, T1699: 2, T1700: 2 };
const plain = value => JSON.parse(JSON.stringify(value));
const idFromLabel = label => label.match(/\((T\d{4}(?:\.\d{3})?)\)$/)?.[1];

function dataContext(source) {
  const context = vm.createContext({});
  vm.runInContext(source.slice(source.indexOf('    var DATA_A ='), source.indexOf('    var buttonStates')), context);
  return context;
}
const data = dataContext(html);
const old = dataContext(baseline);

function functionSource(source, name) {
  const start = source.indexOf('    function ' + name + '(');
  assert.notEqual(start, -1, name);
  const end = source.indexOf('\n    }', start);
  return source.slice(start, end + '\n    }'.length);
}

test('all inline scripts compile', () => {
  const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].filter(m => m[1].trim());
  assert.equal(scripts.length, 2);
  scripts.forEach((m, i) => new vm.Script(m[1], { filename: 'inline-' + i }));
});

test('IDs, translations, placement uniqueness and time coverage', () => {
  const times = Object.values(data.TECHNIQUE_TIMES);
  assert.equal(times.length, 227);
  assert.equal(new Set(times.map(t => t.id)).size, 227);
  const ids = new Set();
  let placements = 0;
  for (const [key, tactic] of Object.entries(data.TACTICS_TO_TECHNIQUES)) {
    assert.ok(tacticMap[key]);
    assert.equal(new Set(tactic.techniques.map(t => t.id)).size, tactic.techniques.length, key);
    for (const item of tactic.techniques) {
      assert.match(item.id, /^T\d{4}$/);
      const time = data.TECHNIQUES_BY_ID[item.id];
      assert.ok(time, item.id);
      for (const lang of ['ru', 'en']) {
        assert.equal(idFromLabel(item[lang]), item.id);
        assert.equal(item[lang], time.translations[lang]);
      }
      assert.equal(time.values.length, 2);
      time.values.forEach(v => assert.ok(Number.isInteger(v) && v >= 0));
      ids.add(item.id);
      placements++;
    }
  }
  assert.equal(placements, 259);
  assert.deepEqual([...ids].sort(), times.map(t => t.id).sort());
});

test('all previous 219 times and cost formulas remain unchanged', () => {
  assert.equal(Object.keys(old.TECHNIQUE_TIMES).length, 219);
  for (const time of Object.values(old.TECHNIQUE_TIMES)) {
    const id = idFromLabel(time.translations.en);
    assert.deepEqual(plain(data.TECHNIQUES_BY_ID[id].values), plain(time.values), id);
  }
  for (const [id, hours] of Object.entries(addedHours)) {
    assert.deepEqual(plain(data.TECHNIQUES_BY_ID[id].values), [hours, 0]);
  }
  for (const name of ['updateAllTotals', 'recalcDynamicBlock', 'getDataForButton',
    'calculateDateDiff', 'calculateDateDiffRange', 'recalcVulnCost', 'recalcFinalValues',
    'updateService15', 'updateService16']) {
    assert.equal(functionSource(html, name), functionSource(baseline, name), name);
  }
  for (const name of ['DATA_A', 'DATA_B', 'DATA_C', 'DATA_SKILL', 'DATA_BUTTONS_1_14',
    'COMBO_FACTORS', 'spread_map', 'vuln_map']) {
    assert.deepEqual(plain(data[name]), plain(old[name]), name);
  }
});

test('exact active Enterprise v20.1 ID and tactic-pair sets', {
  skip: !process.env.CSC_ATTACK_STIX && 'Set CSC_ATTACK_STIX to the downloaded v20.1 Enterprise bundle'
}, () => {
  const bytes = fs.readFileSync(process.env.CSC_ATTACK_STIX);
  assert.equal(createHash('sha256').update(bytes).digest('hex'),
    'f92e8ec8b0e6f56fa310063332ba8f7524330ef51286c1b7e5315f4d2ee0b042');
  const objects = JSON.parse(bytes).objects;
  const ref = item => item.external_references.find(r => r.source_name === 'mitre-attack');
  const techniques = objects.filter(x => x.type === 'attack-pattern' && !x.revoked &&
    !x.x_mitre_deprecated && !x.x_mitre_is_subtechnique && x.x_mitre_domains.includes('enterprise-attack'));
  const targetIds = techniques.map(x => ref(x).external_id).sort();
  assert.deepEqual(Object.keys(data.TECHNIQUES_BY_ID).sort(), targetIds);
  const targetPairs = techniques.flatMap(x => x.kill_chain_phases
    .filter(p => p.kill_chain_name === 'mitre-attack').map(p => ref(x).external_id + '|' + p.phase_name)).sort();
  const pairs = Object.entries(data.TACTICS_TO_TECHNIQUES)
    .flatMap(([key, t]) => t.techniques.map(x => x.id + '|' + tacticMap[key])).sort();
  assert.deepEqual(pairs, targetPairs);
  for (const item of techniques) {
    const id = ref(item).external_id;
    assert.equal(data.TECHNIQUES_BY_ID[id].translations.en, item.name + ' (' + id + ')');
  }
});

// Small in-memory adapter for the jQuery methods used by stage handlers.
// These exercise application callbacks and calculation code, not a real browser or jQuery UI.
class Fields {
  constructor(items) { this.items = items; }
  val(value) {
    if (!arguments.length) return this.items[0].value;
    this.items.forEach(f => { f.value = value == null ? '' : String(value); }); return this;
  }
  data(key, value) {
    if (arguments.length === 1) return this.items[0].data[key];
    this.items.forEach(f => { f.data[key] = value; }); return this;
  }
  prop(key, value) {
    if (arguments.length === 1) return this.items[0].props[key];
    this.items.forEach(f => { f.props[key] = value; }); return this;
  }
  text(value) {
    if (!arguments.length) return this.items[0].text;
    this.items.forEach(f => { f.text = value; }); return this;
  }
  toggle(value) { this.items.forEach(f => { f.visible = value; }); return this; }
  autocomplete(options, key, value) {
    this.items.forEach(f => {
      if (typeof options === 'object') Object.assign(f.options, options);
      else if (options === 'option') f.options[key] = value;
    }); return this;
  }
  on(events, fn) {
    this.items.forEach(f => events.split(' ').forEach(e => (f.handlers[e] ||= []).push(fn))); return this;
  }
  trigger(event) {
    this.items.forEach(f => (f.handlers[event] || []).forEach(fn => fn.call(new Fields([f])))); return this;
  }
}

function stage(lang = 'en') {
  const c = dataContext(html);
  Object.assign(c, { currentLang: lang, $: field => field, updateAllTotals() {}, checkSkillConsistency() {} });
  vm.runInContext(html.slice(html.indexOf('    function getTechniqueId('), html.indexOf('    var dynamicBlockCount')), c);
  vm.runInContext(functionSource(html, 'recalcDynamicBlock'), c);
  const fields = new Map();
  const block = { find(selector) {
    return new Fields(selector.split(',').map(s => {
      s = s.trim();
      if (!fields.has(s)) fields.set(s, { value: s === '.qualification-select' ? 'basic' : '',
        data: {}, props: { disabled: s === '.technique-input' }, handlers: {}, options: {}, text: '', visible: false });
      return fields.get(s);
    }));
  } };
  c.initializeStageCatalog(block);
  const choose = (selector, item) => {
    const input = block.find(selector);
    input.items[0].options.select.call(input, {}, { item });
  };
  const tactic = key => choose('.tactic-input', { value: c.TACTICS_TO_TECHNIQUES[key].translations[lang] });
  const technique = id => {
    const item = block.find('.technique-input').items[0].options.source.find(x => x.techniqueId === id);
    assert.ok(item, id); choose('.technique-input', item);
  };
  return { c, block, choose, tactic, technique, time: () => [block.find('.time-hours').val(), block.find('.time-minutes').val()] };
}

test('technique options are locale-sorted on selection and restore without mutating the catalogue', () => {
  for (const lang of ['ru', 'en']) {
    const s = stage(lang);
    const catalogueBefore = JSON.stringify(s.c.TACTICS_TO_TECHNIQUES);
    const compare = new Intl.Collator(lang, { sensitivity: 'base' }).compare;
    const options = () => plain(s.block.find('.technique-input').items[0].options.source);
    for (const key of Object.keys(s.c.TACTICS_TO_TECHNIQUES)) {
      s.tactic(key);
      const selected = options();
      assert.deepEqual(selected.map(x => x.label), selected.map(x => x.label).sort(compare));
      s.c.restoreDynamicBlock(s.block, {
        tactic: s.c.TACTICS_TO_TECHNIQUES[key].translations[lang],
        time_hours: '1', time_minutes: '17', qualification: 'basic'
      });
      assert.deepEqual(options(), selected, lang + '/' + key);
      assert.deepEqual(s.time(), ['1', '17']);
    }
    s.tactic('execution');
    const expected = lang === 'en'
      ? ['T1197', 'T1651', 'T1059', 'T1609', 'T1699', 'T1698']
      : ['T1059', 'T1698', 'T1699', 'T1651'];
    assert.deepEqual(options().filter(x => expected.includes(x.techniqueId)).map(x => x.techniqueId), expected);
    // Array sources use jQuery UI's order-preserving text filtering. Check the source subsequence;
    // this adapter does not exercise the actual browser widget.
    const term = lang === 'en' ? 'Prompt' : 'инъекция';
    const matches = options().filter(x => new RegExp(term, 'i').test(x.label));
    assert.deepEqual(matches.map(x => x.techniqueId), lang === 'en' ? ['T1699', 'T1698'] : ['T1698', 'T1699']);
    assert.equal(JSON.stringify(s.c.TACTICS_TO_TECHNIQUES), catalogueBefore);
  }
});

test('new techniques select their approved defaults in RU and EN; manual time stays editable', () => {
  for (const lang of ['ru', 'en']) {
    const s = stage(lang);
    for (const [id, hours] of Object.entries(addedHours)) {
      const key = Object.keys(data.TACTICS_TO_TECHNIQUES).find(k => data.TACTICS_TO_TECHNIQUES[k].techniques.some(t => t.id === id));
      s.tactic(key); s.technique(id);
      assert.deepEqual(s.time(), [String(hours), '0']);
      s.block.find('.time-hours').val('1').trigger('input');
      s.block.find('.time-minutes').val('17').trigger('input');
      assert.deepEqual(s.time(), ['1', '17']);
      s.technique(id);
      assert.deepEqual(s.time(), [String(hours), '0']);
    }
    s.tactic('persistence'); s.technique('T1112');
    assert.deepEqual(s.time(), ['2', '0']);
  }
});

test('all 17 previous mismatched placements resolve by ID even with the old label', () => {
  let count = 0;
  for (const lang of ['ru', 'en']) {
    const s = stage(lang);
    for (const [key, tactic] of Object.entries(old.TACTICS_TO_TECHNIQUES)) {
      for (const item of tactic.techniques) {
        if (Object.values(old.TECHNIQUE_TIMES).some(t => t.translations[lang] === item[lang])) continue;
        count++;
        const id = idFromLabel(item[lang]);
        s.tactic(key);
        s.choose('.technique-input', { techniqueId: id, value: item[lang] });
        assert.deepEqual(s.time(), Array.from(data.TECHNIQUES_BY_ID[id].values, String));
        assert.equal(s.block.find('.stage-catalog-status').text(), '');
      }
    }
  }
  assert.equal(count, 17);
});

test('changing tactic clears technique/time/cost; missing time is visible and never inherited', () => {
  const s = stage();
  s.tactic('reconnaissance'); s.technique('T1595');
  s.tactic('execution');
  assert.equal(s.block.find('.technique-input').val(), '');
  assert.deepEqual(s.time(), ['', '']);
  assert.equal(s.block.find('.calc-med').val(), '0');
  s.technique('T1699');
  delete s.c.TECHNIQUES_BY_ID.T1698;
  s.technique('T1698');
  assert.deepEqual(s.time(), ['', '']);
  assert.match(s.block.find('.stage-catalog-status').text(), /No default time/);
  assert.equal(s.block.find('.stage-catalog-status').items[0].visible, true);
});

test('legacy JSON restores 1h17m, qualification, comment and tactic choices across languages', () => {
  for (const lang of ['ru', 'en']) {
    const s = stage(lang);
    const legacy = { tactic: 'Разведка', technique: 'Активное сканирование (T1595)',
      time_hours: '1', time_minutes: '17', qualification: 'advanced', comment: 'Manual duration' };
    s.c.restoreDynamicBlock(s.block, JSON.parse(JSON.stringify(legacy)));
    assert.deepEqual(s.time(), ['1', '17']);
    assert.equal(s.block.find('.qualification-select').val(), 'advanced');
    assert.equal(s.block.find('.stage-comment').val(), legacy.comment);
    assert.equal(s.block.find('.technique-input').prop('disabled'), false);
    assert.ok(s.block.find('.technique-input').items[0].options.source.some(x => x.techniqueId === 'T1595'));
    assert.deepEqual(['.calc-min', '.calc-med', '.calc-max'].map(k => s.block.find(k).val()), ['21', '28', '36']);
    const saved = plain(s.c.getDynamicBlockState(s.block));
    for (const key of Object.keys(legacy)) assert.equal(saved[key], legacy[key]);
    assert.equal(saved.techniqueId, 'T1595');
    assert.equal(saved.tacticKey, 'reconnaissance');
    s.c.restoreDynamicBlock(s.block, saved);
    assert.deepEqual(s.time(), ['1', '17']);
    s.block.find('.tactic-input').trigger('change');
    assert.deepEqual(s.time(), ['1', '17'], 'unchanged tactic must not clear manual time');
    s.technique('T1595');
    assert.deepEqual(s.time(), ['4', '0']);
  }
});

test('renamed and unknown legacy entries keep their text and time; unknown entries are marked', () => {
  for (const legacy of [
    { tactic: 'Persistence', technique: 'Browser Extensions (T1176)' },
    { tactic: 'Unknown old tactic', technique: 'Unknown technique (T9999)' },
    { tactic: 'Execution', technique: 'Free-form old step' }
  ]) {
    const s = stage();
    Object.assign(legacy, { time_hours: '1', time_minutes: '17', qualification: 'top', comment: 'Keep me' });
    s.c.restoreDynamicBlock(s.block, legacy);
    const saved = plain(s.c.getDynamicBlockState(s.block));
    for (const key of Object.keys(legacy)) assert.equal(saved[key], legacy[key]);
    assert.equal(s.block.find('.technique-input').prop('disabled'), false);
    assert.equal(Boolean(s.block.find('.stage-catalog-status').text()), legacy.tactic !== 'Persistence');
    s.c.restoreDynamicBlock(s.block, JSON.parse(JSON.stringify(saved)));
    assert.deepEqual(s.time(), ['1', '17']);
  }
  assert.match(functionSource(html, 'loadSavedState'), /restoreDynamicBlock\(\$block, blockData\)/);
  assert.match(functionSource(html, 'getCurrentState'), /getDynamicBlockState\(\$\(this\)\)/);
});
