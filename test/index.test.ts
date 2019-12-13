// const assert = require('assert');
import scrypt = require('../src/index');
const Demo = scrypt.require('../test/contracts/sum.scrypt');
import { expect } from 'chai';
import 'mocha';

describe('First test', () => {
  let demo;

  before(() => {
    demo = new Demo(4, 7);
  });

  it('should return true', () => {
    const result = demo.unlock(11);
    expect(result).to.equal(true);
  });

  it('should return false', () => {
    const result = demo.unlock(9);
    expect(result).to.equal(false);
  });
});