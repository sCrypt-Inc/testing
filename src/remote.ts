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
const buildScriptLockTx = (utxos, scriptPubKey, privateKey, amount) => {
    const tx = new bsv.Transaction().from(utxos);
    tx.addOutput(new bsv.Transaction.Output({
        script: scriptPubKey,
        satoshis: amount,
    }));
    tx.change(privateKey.toAddress());
    if (tx.getFee() < MIN_FEE) {
        tx.fee(MIN_FEE);
    }
    return tx.sign(privateKey);
};

// unlock fund from a script
const buildScriptUnlockTx = (prevTxId, scriptPubKey, inputAmount, newScriptPubKey, outputAmount) => {
    const tx = new bsv.Transaction().addInput(new bsv.Transaction.Input({
        prevTxId,
        outputIndex: 0,
        script: new bsv.Script(),   // placeholder
    }), scriptPubKey, inputAmount);
    tx.addOutput(new bsv.Transaction.Output({
        script: newScriptPubKey,
        satoshis: outputAmount,
    }));
    // no need to sign since scriptSig is already set
    return tx;
};

const sendTx = async (txhex) => {
    const { data: txid } = await axios.post(`${API_PREFIX}/tx/raw`, {
        txhex,
    });
    return txid;
};

// send tx to send funds to locking script
const lockScriptTx = async (scriptPubKeyStr, key, amount) => {
    const scriptPubKey = bsv.Script.fromASM(scriptPubKeyStr);
    const privateKey = new bsv.PrivateKey(key);

    // step 1: fetch utxos
    const utxos = await fetchUtxos(privateKey.toAddress());

    // step 2: build the locking tx and sign it
    const lockingTx = buildScriptLockTx(utxos, scriptPubKey, privateKey, amount);

    // step 3: serialize and broadcast the locking tx
    return await sendTx(lockingTx.serialize());
};

// send tx to unlock previously locked fund
const unlockScriptTx = async (scriptSigStr, lockingTxid, scriptPubKeyStr, inputAmount, newScriptPubKeyStr, outputAmount) => {
    const scriptSig = bsv.Script.fromASM(scriptSigStr);
    const scriptPubKey = bsv.Script.fromASM(scriptPubKeyStr);
    const newScriptPubKey = bsv.Script.fromASM(newScriptPubKeyStr);

    // step 1: build the unlocking tx
    const unlockingTx = buildScriptUnlockTx(lockingTxid, scriptPubKey, inputAmount, newScriptPubKey, outputAmount);
    unlockingTx.inputs[INPUT_IDX].setScript(scriptSig);

    // step 2: serialize and send it
    return await sendTx(unlockingTx.serialize());
};

// helper function to get sighash preimage
const getSighashPreimage = (lockingTxid, scriptPubKeyStr, inputAmount, newScriptPubKeyStr, outputAmount) => {
    const scriptPubKey = bsv.Script.fromASM(scriptPubKeyStr);
    const newScriptPubKey = bsv.Script.fromASM(newScriptPubKeyStr);
    const unlockingTx = buildScriptUnlockTx(lockingTxid, scriptPubKey, inputAmount, newScriptPubKey, outputAmount);
    const preimage = bsv.Transaction.sighash.sighashPreimage(unlockingTx, SIGHASH_TYPE, INPUT_IDX, scriptPubKey, new bsv.crypto.BN(inputAmount), FLAGS);
    return preimage.toString('hex');
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
    getSighashPreimage,
    showError,
};

export { lockScriptTx, unlockScriptTx, getSighashPreimage, showError };
