'use strict';

/**
 * test locally
 */

import childProcess = require('child_process');
import fs = require('fs');
import path = require('path');
import bsv = require('bsv');
const BN = bsv.crypto.BN;
const Interpreter = bsv.Script.Interpreter;

const FLAGS = Interpreter.SCRIPT_VERIFY_MINIMALDATA | Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID | Interpreter.SCRIPT_ENABLE_MAGNETIC_OPCODES | Interpreter.SCRIPT_ENABLE_MONOLITH_OPCODES;

const ASM_SUFFIX = '_asm.json';
const AST_SUFFIX = '_ast.json';

// convert int literals to script ASM format
function int2Asm(num: number | BigInt): string {
  if (num === -1) { return 'OP_1NEGATE'; }

  if (num >= 0 && num <= 16) { return 'OP_' + num; }

  const n = typeof num === 'number' ? BN.fromNumber(num) : new BN(num.toString());
  const m = n.toSM({ endian: 'little' });
  return m.toString('hex');
}

// TODO: error handling
// convert literals to script ASM format
function literal2Asm(l: boolean | string | number | BigInt): string {
  // bool
  if (l === false)  { return 'OP_FALSE'; }
  if (l === true)   { return 'OP_TRUE'; }

  // bytes
  if (typeof l === 'string') {
    return l;
  }

  // int
  return int2Asm(l);
}

/**
 * construct a class reflecting sCrypt contract
 * @param {sourcePath} - path of contract source file (.scrypt)
 * (the follwoing parameters are only needed to check signature validity for some opcodes like OP_CHECKSIG)
 * @param {Transaction} tx - the Transaction containing the scriptSig in one input
 * @param {number} nin - index of the transaction input containing the scriptSig verified.
 * @param {number} inputSatoshis - amount in satoshis of the input to be verified (when FORKID signhash is used)
 */
function buildContractClass(sourcePath, tx?, nin?: number, inputSatoshis?: number) {
  if (!sourcePath) {
    throw new Error('You must provide the source file of the contract when creating a contract.');
  }
  const res = compile(sourcePath);

  const Contract = class {
    private scriptPubKey: string[];

    public getScriptPubKey(): string {
      return this.scriptPubKey.join(' ');
    }

    public setScriptPubKey(scriptPubKey: string) {
      this.scriptPubKey = scriptPubKey.split(' ');
    }

    constructor() {
      let args = Array.prototype.slice.call(arguments);
      // handle case of no ctor
      const ctorParams = res.ctor ? res.ctor.params : res.properties;
      // TODO: arguments type check, besides number check
      if (args.length !== ctorParams.length) {
        throw new Error(`Expected ${ctorParams.length} constructor arguments, but got ${args.length}`);
      }
      args = args.map((arg) => literal2Asm(arg));
      const ctorParamNames = ctorParams.map((param) => param.name.startsWith('this.') ? param.name.substring(5) : param.name);

      // instantiate contract w/ constructor arguments
      this.scriptPubKey = res.opcodes.map((opcode) => {
          if (opcode.startsWith('$')) {
            const param = opcode.substring(1);
            const idx = ctorParamNames.indexOf(param);
            if (idx === -1) {
              throw new Error(`"$${param}" in compiled script is not a constructor parameter, something in compiler is wrong`);
            }
            // substitute $x with x value
            return args[idx];
          }
          return opcode;
        },
      );
    }
  };

  res.functions.map((func, index: number) => {
    // contract functions
    Contract.prototype[func.name] = function(): boolean {
      let args = Array.prototype.slice.call(arguments);
      if (args && func.params && args.length !== func.params.length) {
        // TODO: better error message
        throw new Error('wrong arg#');
      }

      args = args.map((arg) => literal2Asm(arg));
      let scriptSig = args.join(' ');
      if (res.functions.length > 1) {
        // append function selector if there are multiple public functions
        scriptSig += ' ' + literal2Asm(index + 1);
      }

      const lockingScript = bsv.Script.fromASM(this.getScriptPubKey());
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
  return [
    path.join(path.dirname(srcPath), srcName + AST_SUFFIX),
    path.join(path.dirname(srcPath), srcName + ASM_SUFFIX)
  ];
}

// sourcePath -> opcodes
// debug: debug/production mode
function compile(sourcePath: string, debug = true) {
  const [astFileName, asmFileName] = getCompiledFilePath(sourcePath);

  try {
    const cmd = `node "${path.join(__dirname, '../../scryptc/scrypt.js')}" compile "${sourcePath}" --asm --ast ${debug ? '--debug' : ''}`;
    const output = childProcess.execSync(cmd, {cwd: path.dirname(sourcePath)}).toString();
    if (!output.includes('Error')) {
      const asmStr = fs.readFileSync(asmFileName, 'utf8');
      const opcodes = debug ? JSON.parse(asmStr).output.map(e => e.opcode) : asmStr.split(' ');
      const ast = JSON.parse(fs.readFileSync(astFileName, 'utf8'))[sourcePath];
      // only for the last main contract
      const mainContract = ast.contracts[ast.contracts.length - 1];
      return {
        opcodes,
        ctor: mainContract.constructor,
        properties: mainContract.properties,
        // public functions only
        functions: mainContract.functions.filter((func) => func.visibility === 'Public'),
      };
    } else {
      throw new Error('Compilation fails: ' + output);
    }
  } catch (err) {
    const error = err.code || err.toString();
    throw new Error('Compilation error: ' + error);
  } finally {
    if (fs.existsSync(asmFileName)) {
      fs.unlinkSync(asmFileName);
    }
    if (fs.existsSync(astFileName)) {
      fs.unlinkSync(astFileName);
    }
  }
}

module.exports = {
  buildContractClass,
  bsv,
  int2Asm,
  literal2Asm,
};

export { buildContractClass, bsv, int2Asm, literal2Asm };
