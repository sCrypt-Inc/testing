import path = require('path');
import { expect } from 'chai';
import 'mocha';

import { buildContractClass } from '../../src/index';

describe('Test sCrypt Contract Demo', () => {
  let demo;

  before(() => {
    const Demo = buildContractClass(path.join(__dirname, '../contracts/demo.scrypt'));
    demo = new Demo(4, 7);
  });

  it('should return true', () => {
    expect(demo.unlock(4 + 7)).to.equal(true);
  });

  it('should return false', () => {
    expect(demo.unlock(0)).to.equal(false);
  });
});
