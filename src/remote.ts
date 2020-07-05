'use strict';

/**
 * test remotely: e.g., on testnet
 */
import axios from 'axios';
import bsv = require('bsv');

const NETWORK = 'test';
const API_PREFIX = 'https://api.whatsonchain.com/v1/bsv/' + NETWORK;
// TODO: adapt to script/tx size using fee per byte
const MIN_FEE = 546;
const INPUT_IDX = 0;
const FLAGS = bsv.Script.Interpreter.SCRIPT_VERIFY_MINIMALDATA | bsv.Script.Interpreter.SCRIPT_ENABLE_SIGHASH_FORKID | bsv.Script.Interpreter.SCRIPT_ENABLE_MAGNETIC_OPCODES | bsv.Script.Interpreter.SCRIPT_ENABLE_MONOLITH_OPCODES;
const SIGHASH_TYPE = bsv.crypto.Signature.SIGHASH_ALL | bsv.crypto.Signature.SIGHASH_FORKID;
const SIGHASH_ALLANY = SIGHASH_TYPE | bsv.crypto.Signature.SIGHASH_ANYONECANPAY

const fetchUtxos = async (address) => {
    let { data: utxos } = await axios.get(`${API_PREFIX}/address/${address}/unspent`);
    utxos = utxos.map((utxo) => ({
        txId: utxo.tx_hash,
        outputIndex: utxo.tx_pos,
        satoshis: utxo.value,
        script: bsv.Script.buildPublicKeyHashOut(address).toHex(),
    }));
    return utxos;
};

// lock fund in a script
const buildScriptLockTx = (utxos, lockingScript, privateKey, amount) => {
    const tx = new bsv.Transaction().from(utxos);
    tx.addOutput(new bsv.Transaction.Output({
        script: lockingScript,
        satoshis: amount,
    }));
    tx.change(privateKey.toAddress());
    if (tx.getFee() < MIN_FEE) {
        tx.fee(MIN_FEE);
    }
    return tx.sign(privateKey);
};

// unlock fund from a script
const buildScriptUnlockTx = (prevTxId, lockingScript, inputAmount, newLockingScript, outputAmount) => {
    const tx = new bsv.Transaction().addInput(new bsv.Transaction.Input({
        prevTxId,
        outputIndex: 0,
        script: new bsv.Script(),   // placeholder
    }), lockingScript, inputAmount);
    tx.addOutput(new bsv.Transaction.Output({
        script: newLockingScript,
        satoshis: outputAmount,
    }));
    // no need to sign since unlockingScript is already set
    return tx;
};

// unlock funds from a script, but, add an extra input (funding) and output (change)
const buildFundedScriptUnlockTx = (utxos, privateKey, prevTxId,
                                   lockingScript, inputAmount, newLockingScript, outputAmount) => {

    // derive PKH from Private Key - to sign P2PKH funding
    const fundingPubKey = bsv.PublicKey.fromPrivateKey(privateKey).toBuffer();
    const fundingPKH = bsv.crypto.Hash.sha256ripemd160(fundingPubKey);
    const fundingPKHstr = fundingPKH.toString('hex');
    const fundingLockingScript = bsv.Script.fromASM('OP_DUP OP_HASH160 ' + fundingPKHstr + ' OP_EQUALVERIFY OP_CHECKSIG');

    const fundingAmount = utxos[0].satoshis;
    const fundingTxid = utxos[0].txId;
    const fundingOutputIndex = utxos[0].outputIndex;

    const tx = new bsv.Transaction();

    tx.addInput(new bsv.Transaction.Input({
        prevTxId,
        outputIndex: 0,
        script: new bsv.Script(),   // placeholder
    }), lockingScript, inputAmount);

    tx.addInput(new bsv.Transaction.Input({
        prevTxId: fundingTxid,
        outputIndex: fundingOutputIndex,
        script: new bsv.Script(),
    }), fundingLockingScript, fundingAmount);

    tx.addOutput(new bsv.Transaction.Output({
        script: newLockingScript,
        satoshis: outputAmount,
    }));

    tx.change(privateKey.toAddress());

    if (tx.getFee() < MIN_FEE) {
        tx.fee(MIN_FEE);
    }

    // We'll sign it later
    return tx;
};

const sendTx = async (txhex) => {
    const { data: txid } = await axios.post(`${API_PREFIX}/tx/raw`, {
        txhex,
    });
    return txid;
};

// send tx to send funds to locking script
const lockScriptTx = async (lockingScriptStr, key, amount) => {
    const lockingScript = bsv.Script.fromASM(lockingScriptStr);
    const privateKey = new bsv.PrivateKey(key);

    // step 1: fetch utxos
    const utxos = await fetchUtxos(privateKey.toAddress());

    // step 2: build the locking tx and sign it
    const lockingTx = buildScriptLockTx(utxos, lockingScript, privateKey, amount);

    // step 3: serialize and broadcast the locking tx
    return await sendTx(lockingTx.serialize());
};

// send tx to unlock previously locked fund
const unlockScriptTx = async (unlockingScriptStr, lockingTxid, lockingScriptStr, inputAmount, newLockingScriptStr, outputAmount) => {
    const unlockingScript = bsv.Script.fromASM(unlockingScriptStr);
    const lockingScript = bsv.Script.fromASM(lockingScriptStr);
    const newLockingScript = bsv.Script.fromASM(newLockingScriptStr);

    // step 1: build the unlocking tx
    const unlockingTx = buildScriptUnlockTx(lockingTxid, lockingScript, inputAmount, newLockingScript, outputAmount);
    unlockingTx.inputs[INPUT_IDX].setScript(unlockingScript);

    // step 2: serialize and send it
    return await sendTx(unlockingTx.serialize());
};

// send tx to fund and unlock previously locked funds, but, add extra input (funding) and output (change)
const unlockFundedScriptTx = async (key, unlockingScriptStr, lockingTxid, lockingScriptStr, inputAmount, newLockingScriptStr, outputAmount) => {
    const unlockingScript = bsv.Script.fromASM(unlockingScriptStr);
    const lockingScript = bsv.Script.fromASM(lockingScriptStr);
    const newLockingScript = bsv.Script.fromASM(newLockingScriptStr);

    // step 1: fetch utxos
    const privateKey = new bsv.PrivateKey(key);
    const utxos = await fetchUtxos(privateKey.toAddress());

    // step 2: build the unlocking tx
    const unlockingTx = buildFundedScriptUnlockTx(utxos, privateKey, lockingTxid, lockingScript, inputAmount, newLockingScript, outputAmount);

    // step 3: set the unlockingScript on the zeroth input
    unlockingTx.inputs[INPUT_IDX].setScript(unlockingScript);

    // TODO: simplify as this is just unlocking p2pkh
    // step 4: sign the external funding input
    const txSig1 = new bsv.Transaction.Signature({
            publicKey: bsv.PublicKey.fromPrivateKey(privateKey),
            prevTxId: unlockingTx.inputs[INPUT_IDX + 1].prevTxId,
            outputIndex: unlockingTx.inputs[INPUT_IDX + 1].outputIndex,
            inputIndex: INPUT_IDX + 1,
            signature: bsv.Transaction.Sighash.sign(unlockingTx, privateKey, SIGHASH_TYPE,
                               INPUT_IDX + 1,
                               unlockingTx.inputs[INPUT_IDX + 1].output.script,
                               unlockingTx.inputs[INPUT_IDX + 1].output.satoshisBN),
            sigtype: SIGHASH_TYPE,
        });

    unlockingTx.inputs[INPUT_IDX + 1].setScript(bsv.Script.buildPublicKeyHashIn(
            txSig1.publicKey,
            txSig1.signature.toDER(),
            txSig1.sigtype,
    ));

    // step 5: serialize and send it.
    return await sendTx(unlockingTx.serialize());
};

// helper function to get sighash preimage
const getSighashPreimage = (lockingTxid, lockingScriptStr, inputAmount, newLockingScriptStr, outputAmount) => {
    const lockingScript = bsv.Script.fromASM(lockingScriptStr);
    const newLockingScript = bsv.Script.fromASM(newLockingScriptStr);
    const unlockingTx = buildScriptUnlockTx(lockingTxid, lockingScript, inputAmount, newLockingScript, outputAmount);
    const preimage = bsv.Transaction.sighash.sighashPreimage(unlockingTx, SIGHASH_TYPE, INPUT_IDX, lockingScript, new bsv.crypto.BN(inputAmount), FLAGS);
    return preimage.toString('hex');
};

// helper function to get signature
const getSignature = (lockingTxid, privateKey, lockingScriptStr, inputAmount, newLockingScriptStr, outputAmount) => {
    const lockingScript = bsv.Script.fromASM(lockingScriptStr);
    const newLockingScript = bsv.Script.fromASM(newLockingScriptStr);
    const unlockingTx = buildScriptUnlockTx(lockingTxid, lockingScript, inputAmount, newLockingScript, outputAmount);
    const sig = bsv.Transaction.sighash.sign(unlockingTx, privateKey, SIGHASH_TYPE, INPUT_IDX, lockingScript, new bsv.crypto.BN(inputAmount), FLAGS).toTxFormat();
    return sig.toString('hex');
};

// helper function to get sighash preimage, but, add extra input (funding) and output (change)
// Use alternate build: buildFundedScriptUnlockTx()
const getFundedSighashPreimage = async (key, lockingTxid, lockingScriptStr, inputAmount, newLockingScriptStr, outputAmount) => {

    const lockingScript = bsv.Script.fromASM(lockingScriptStr);
    const newLockingScript = bsv.Script.fromASM(newLockingScriptStr);

    // step 1: fetch utxos
    const privateKey = new bsv.PrivateKey(key);
    const utxos = await fetchUtxos(privateKey.toAddress());

    const unlockingTx = buildFundedScriptUnlockTx(utxos, privateKey, lockingTxid, lockingScript, inputAmount, newLockingScript, outputAmount);

    const preimage = bsv.Transaction.sighash.sighashPreimage(unlockingTx, SIGHASH_ALLANY, INPUT_IDX, lockingScript, new bsv.crypto.BN(inputAmount), FLAGS);

    const fee1 = unlockingTx._inputAmount - unlockingTx._outputAmount;
    const satsChange = unlockingTx.outputs[1]._satoshis;

    return { preimage: preimage.toString('hex'),
             change: satsChange,
             fee: fee1,
    };
};

// print out error
const showError = (error) => {
    // Error
    if (error.response) {
        // The request was made and the server responded with a status code
        // that falls out of the range of 2xx
        console.log('Failed - StatusCodeError: ' + error.response.status + ' - "' + error.response.data + '"');
        // console.log(error.response.headers);
    } else if (error.request) {
        // The request was made but no response was received
        // `error.request` is an instance of XMLHttpRequest in the
        // browser and an instance of
        // http.ClientRequest in node.js
        console.log(error.request);
    } else {
        // Something happened in setting up the request that triggered an Error
        console.log('Error:', error.message);
    }
    console.log(error.config);
};

module.exports = {
    lockScriptTx,
    unlockScriptTx,
    unlockFundedScriptTx,
    getSighashPreimage,
    getFundedSighashPreimage,
    getSignature,
    showError,
};

export { lockScriptTx, unlockScriptTx, unlockFundedScriptTx, getSighashPreimage, getFundedSighashPreimage, getSignature, showError };
