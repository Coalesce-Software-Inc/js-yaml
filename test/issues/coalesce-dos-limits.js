'use strict';


const assert = require('assert');
const yaml   = require('../../');


function mergeChain(count) {
  const lines = [ 'a0: &a0 { k0: 0 }' ];

  for (let i = 1; i < count; i++) {
    lines.push('a' + i + ': &a' + i + ' { <<: *a' + (i - 1) + ', k' + i + ': ' + i + ' }');
  }

  return lines.join('\n') + '\n';
}

function emptyMergeSources(anchors, refsPerMerge, merges) {
  const lines = [];
  const refs = [];

  for (let i = 0; i < anchors; i++) lines.push('e' + i + ': &e' + i + ' {}');
  for (let i = 0; i < refsPerMerge; i++) refs.push('*e' + (i % anchors));
  for (let i = 0; i < merges; i++) lines.push('m' + i + ': { <<: [' + refs.join(', ') + '] }');

  return lines.join('\n') + '\n';
}


describe('DoS limits (CVE-2026-59869, GHSA-5p4m-2wfm-xmqj, CVE-2026-84375)', function () {
  it('rejects merge-key chains past maxTotalMergeKeys', function () {
    assert.throws(() => yaml.load(mergeChain(200)), /merge keys exceeded maxTotalMergeKeys \(10000\)/);
  });

  it('keeps ordinary merges working and honours maxTotalMergeKeys', function () {
    assert.deepStrictEqual(yaml.load(mergeChain(3)).a2, { k0: 0, k1: 1, k2: 2 });
    assert.throws(() => yaml.load(mergeChain(3), { maxTotalMergeKeys: 3 }), /maxTotalMergeKeys \(3\)/);
    assert.strictEqual(Object.keys(yaml.load(mergeChain(200), { maxTotalMergeKeys: -1 }).a199).length, 200);
  });

  it('shares the merge budget across documents in loadAll', function () {
    const doc = '---\na: &a { k1: 1, k2: 2 }\nb: { <<: *a }\n';

    assert.doesNotThrow(() => yaml.loadAll(doc + doc, null, { maxTotalMergeKeys: 6 }));
    assert.throws(() => yaml.loadAll(doc + doc, null, { maxTotalMergeKeys: 5 }), /maxTotalMergeKeys/);
  });

  it('charges empty merge sources against maxTotalMergeKeys', function () {
    assert.throws(() => yaml.load(emptyMergeSources(10, 100, 200)), /merge keys exceeded maxTotalMergeKeys/);
  });

  it('rejects merge sequences longer than 100 entries', function () {
    assert.doesNotThrow(() => yaml.load(emptyMergeSources(1, 100, 1)));
    assert.throws(() => yaml.load(emptyMergeSources(1, 101, 1)), /abnormal merge sequence size/);
  });

  it('resolves large !!omap values in linear time and still rejects duplicate keys', function () {
    const pairs = [];

    for (let i = 0; i < 100000; i++) pairs.push('- k' + i + ': ' + i);

    const seq = pairs.join('\n') + '\n';
    let started = Date.now();
    yaml.load(seq);
    const seqMs = Math.max(Date.now() - started, 20);

    started = Date.now();
    const result = yaml.load('--- !!omap\n' + seq);
    const omapMs = Date.now() - started;

    assert.strictEqual(result.length, 100000);
    assert.ok(omapMs < seqMs * 10, '!!omap took ' + omapMs + 'ms vs ' + seqMs + 'ms for the plain sequence');
    assert.throws(
      () => yaml.load('--- !!omap\n- a: 1\n- b: 2\n- a: 3\n'),
      /cannot resolve a node with !<tag:yaml.org,2002:omap> explicit tag/
    );
    const special = yaml.load('--- !!omap\n- __proto__: 1\n- constructor: 2\n');

    assert.deepStrictEqual(special.map(pair => Object.keys(pair)), [ [ '__proto__' ], [ 'constructor' ] ]);
  });
});
