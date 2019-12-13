// const assert = require('assert');
import scrypt = require('../src/index');
import path = require('path');
import { expect } from 'chai';
import 'mocha';

describe('First test', () => {
  let demo;

  before(() => {
    const Demo = scrypt.require(path.join(__dirname, 'contracts/sum.scrypt'));
    demo = new Demo(4, 7);
  });

  it('should return true', () => {
    expect(demo.unlock(4 + 7)).to.equal(true);
  });

  it('should return false', () => {
    expect(demo.unlock(0)).to.equal(false);
  });
});
