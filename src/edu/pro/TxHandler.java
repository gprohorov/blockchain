package edu.pro;

import java.util.ArrayList;
import java.util.List;

public class TxHandler {

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    private UTXOPool utxoPool;

    public TxHandler() {}

    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = utxoPool;
    }

    public UTXOPool getUtxoPool() {
        return utxoPool;
    }

    public void setUtxoPool(UTXOPool utxoPool) {
        this.utxoPool = utxoPool;
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        double inputSum = 0;
        double outputSum = 0;
        List<UTXO> usedUTXOList = new ArrayList<>();

        for (int i = 0;i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            int outputIndex = input.outputIndex;
            byte[] prevTrxHash = input.prevTxHash;
            byte[] sign = input.signature;

            UTXO utxo = new UTXO(prevTrxHash, outputIndex);
            Transaction.Output output = this.getUtxoPool().getTxOutput(utxo);
            byte[] message = tx.getRawDataToSign(i);

            if ( (!this.getUtxoPool().contains(utxo))
                    || (!Crypto.verifySignature(output.address,message,sign))
                    || (usedUTXOList.contains(utxo))
                ) {
                return false;
            }else {
                usedUTXOList.add(utxo);
                inputSum += output.value;
            }
        }

        for (int i = 0; i < tx.numOutputs(); i++) {
            if (tx.getOutput(i).value < 0) {
                return false;
            }else {outputSum += tx.getOutput(i).value;}
        }

        if (inputSum >= outputSum) { return false;  }

        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {

        ArrayList<Transaction> validTrxs = new ArrayList<>();
        for (Transaction trx : possibleTxs) {
            if (this.isValidTx(trx)) {
                validTrxs.add(trx);
                for (Transaction.Input input : trx.getInputs()) {
                    int outputIndex = input.outputIndex;
                    byte[] prevTxHash = input.prevTxHash;
                    UTXO utxo = new UTXO(prevTxHash, outputIndex);
                    this.getUtxoPool().removeUTXO(utxo);
                }

                byte[] hash = trx.getHash();
                for (int i = 0; i < trx.numOutputs(); i++) {
                    UTXO utxo = new UTXO(hash, i);
                    this.getUtxoPool().addUTXO(utxo, trx.getOutput(i));
                }
            }
        }

        Transaction[] validTrxsArray = new Transaction[validTrxs.size()];
        validTrxsArray = validTrxs.toArray(validTrxsArray);
        return validTrxsArray;
    }

}
