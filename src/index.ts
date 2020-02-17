'use strict';

import childProcess = require('child_process');
import fs = require('fs');
import path = require('path');
import bsv = require('bsv');
const BN = bsv.crypto.BN;
const Interpreter = bsv.Script.Interpreter;

const FLAGS = Interpreter.SCRIPT_VERIFY_MINIMALDATA | Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID | Interpreter.SCRIPT_ENABLE_MAGNETIC_OPCODES | Interpreter.SCRIPT_ENABLE_MONOLITH_OPCODES

const COMPILE_TIMEOUT = 30000; // in ms
const ASM_SUFFIX = '_asm.json';
const AST_SUFFIX = '_ast.json';

function int2sm(num: number): string {
  if (num === -1) { return 'OP_1NEGATE'; }

  if (num >= 0 && num <= 16) { return 'OP_' + num; }

  const n = BN.fromNumber(num);
  const m = n.toSM({ endian: 'little' });
  return m.toString('hex');
}

// TODO: error handling
// convert literals to script ASM format
function literal2Asm(l: boolean | number | string): string {
  // bool
  if (l === false) { return 'OP_FALSE'; }
  if (l === true) { return 'OP_TRUE'; }

  // hex int/bytes
  if (typeof l === 'string') {
    if (l.startsWith('0x')) { return l.slice(2);
  } }

  // decimal int
  if (typeof l === 'number') {
    return int2sm(l);
  }
}

/**
 * construct a class reflecting sCrypt contract
 * @param {sourcePath} - path of contract source file (.scrypt)
 * (the follwoing parameters are only needed to check signature validity for some opcodes like OP_CHECKSIG)
 * @param {Transaction} tx - the Transaction containing the scriptSig in one input 
 * @param {number} nin - index of the transaction input containing the scriptSig verified.
 * @param {number} inputSatoshis - amount in satoshis of the input to be verified (when FORKID signhash is used)
 */
function buildContractClass(sourcePath, tx, nin: number, inputSatoshis: number) {
  if (!sourcePath) {
    throw new Error('You must provide the source file of the contract when creating a contract.');
  }
  const res = compile(sourcePath);

  const Contract = class {
    // properties
    public static scriptPubKey = res.opcodes;

    constructor() {
      let args = Array.prototype.slice.call(arguments);
      // TODO: handle case of no ctor
      // TODO: arguments type check, besides number check
      if (args && res.ctor.params && args.length !== res.ctor.params.length) {
        // TODO: better error message
        throw new Error('wrong arg#');
      }
      args = args.map((arg) => literal2Asm(arg));
      // console.log('scriptPubKey before: ' + Contract.scriptPubKey.join(' '));
      // TODO: replace $x with x value, not simply based on position, since $x may not be at the beginning after optimization
      Contract.scriptPubKey.splice(0, args.length, ...args);
      // console.log('scriptPubKey after: ' + Contract.scriptPubKey.join(' '));
    }
  };

  res.functions.map((func) => {
    // contract functions
    Contract.prototype[func.name] = function(): boolean {
      let args = Array.prototype.slice.call(arguments);
      if (args && func.params && args.length !== func.params.length) {
        // TODO: better error message
        throw new Error('wrong arg#');
      }

      args = args.map((arg) => literal2Asm(arg));
      const scriptSig = args.join(' ');

      const lockingScript = bsv.Script.fromASM(Contract.scriptPubKey.join(' '));
      const unlockingScript = bsv.Script.fromASM(scriptSig);

      const si = bsv.Script.Interpreter();
      // TODO: return error message (si.errstr) also when evaluating to false
      return si.verify(unlockingScript, lockingScript, tx, nin, FLAGS, new bsv.crypto.BN(inputSatoshis));
    };
  });

  return Contract as any;
}

function getCompiledFilePath(srcPath: string): [string /* ast */, string /* asm */] {
  const extension = path.extname(srcPath);
  const srcName = path.basename(srcPath, extension);
  return [srcName + AST_SUFFIX, srcName + ASM_SUFFIX];
}

// sourcePath -> opcodes
function compile(sourcePath) {
  const [astFileName, asmFileName] = getCompiledFilePath(sourcePath);

  try {
    const cmd = `node_modules/.bin/scryptc -- compile ${sourcePath} --asm --ast`;
    const output = childProcess.execSync(cmd, { timeout: COMPILE_TIMEOUT }).toString();
    if (!output.includes('Error')) {
      const opcodes = fs.readFileSync(asmFileName, 'utf8').trim().split(' ');
      const ast = JSON.parse(fs.readFileSync(astFileName, 'utf8'))[sourcePath];
      // only for the last main contract
      const mainContract = ast.contracts[ast.contracts.length - 1];
      return {
        opcodes,
        ctor: mainContract.constructor,
        // public functions only
        functions: mainContract.functions.filter((func) => func.visibility === 'Public'),
      };
    } else {
      throw new Error('Compilation fails: ' + output);
    }
  } catch (err) {
    const error = err.code === 'ETIMEDOUT'
      ? 'Compilation timed out, likely too many loops. Please reduce loops and retry.'
      : err.code || err.toString();
    throw new Error('Compilation error: ' + error);
  } finally {
    fs.unlinkSync(asmFileName);
    fs.unlinkSync(astFileName);
  }
}

module.exports = {
  buildContractClass,
  bsv,
};
