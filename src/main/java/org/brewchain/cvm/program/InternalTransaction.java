package org.mos.cvm.program;

import static org.apache.commons.lang3.ArrayUtils.isEmpty;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.mos.cvm.base.DataWord;
import org.mos.cvm.utils.ByteUtil;
import org.mos.cvm.utils.RLP;


public class InternalTransaction {
	
    private byte[] parentHash;
    private int deep;
    private int index;
    private boolean rejected = false;
    private String note;

    public InternalTransaction(byte[] rawData) {
//        super(rawData);
    }

    public InternalTransaction(byte[] parentHash, int deep, int index, byte[] nonce, DataWord gasPrice, DataWord gasLimit,
                               byte[] sendAddress, byte[] receiveAddress, byte[] value, byte[] data, String note) {

//        super(nonce, getData(gasPrice), getData(gasLimit), receiveAddress, nullToEmpty(value), nullToEmpty(data));

        this.parentHash = parentHash;
        this.deep = deep;
        this.index = index;
//        this.sendAddress = nullToEmpty(sendAddress);
        this.note = note;
//        this.parsed = true;
    }

    private static byte[] getData(DataWord gasPrice) {
        return (gasPrice == null) ? ByteUtil.EMPTY_BYTE_ARRAY : gasPrice.getData();
    }

    public void reject() {
        this.rejected = true;
    }


    public int getDeep() {
        rlpParse();
        return deep;
    }

    public int getIndex() {
        rlpParse();
        return index;
    }

    public boolean isRejected() {
        rlpParse();
        return rejected;
    }

    public String getNote() {
        rlpParse();
        return note;
    }

//    @Override
//    public byte[] getSender() {
//        rlpParse();
//        return sendAddress;
//    }

    public byte[] getParentHash() {
        rlpParse();
        return parentHash;
    }

//    @Override
//    public byte[] getEncoded() {
//        if (rlpEncoded == null) {
//
//            byte[] nonce = getNonce();
//            boolean isEmptyNonce = isEmpty(nonce) || (getLength(nonce) == 1 && nonce[0] == 0);
//
//            this.rlpEncoded = RLP.encodeList(
//                    RLP.encodeElement(isEmptyNonce ? null : nonce),
//                    RLP.encodeElement(this.parentHash),
//                    RLP.encodeElement(getSender()),
//                    RLP.encodeElement(getReceiveAddress()),
//                    RLP.encodeElement(getValue()),
//                    RLP.encodeElement(getGasPrice()),
//                    RLP.encodeElement(getGasLimit()),
//                    RLP.encodeElement(getData()),
//                    RLP.encodeString(this.note),
//                    encodeInt(this.deep),
//                    encodeInt(this.index),
//                    encodeInt(this.rejected ? 1 : 0)
//            );
//        }
//
//        return rlpEncoded;
//    }
//
//    @Override
//    public byte[] getEncodedRaw() {
//        return getEncoded();
//    }
//
//    @Override
    public synchronized void rlpParse() {
//        if (parsed) return;
//        RLPList decodedTxList = RLP.decode2(rlpEncoded);
//        RLPList transaction = (RLPList) decodedTxList.get(0);
//
//        setNonce(transaction.get(0).getRLPData());
//        this.parentHash = transaction.get(1).getRLPData();
//        this.sendAddress = transaction.get(2).getRLPData();
//        setReceiveAddress(transaction.get(3).getRLPData());
//        setValue(transaction.get(4).getRLPData());
//        setGasPrice(transaction.get(5).getRLPData());
//        setGasLimit(transaction.get(6).getRLPData());
//        setData(transaction.get(7).getRLPData());
//        this.note = new String(transaction.get(8).getRLPData());
//        this.deep = decodeInt(transaction.get(9).getRLPData());
//        this.index = decodeInt(transaction.get(10).getRLPData());
//        this.rejected = decodeInt(transaction.get(11).getRLPData()) == 1;
//
//        this.parsed = true;
    }


    private static byte[] intToBytes(int value) {
        return ByteBuffer.allocate(Integer.SIZE / Byte.SIZE)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(value)
                .array();
    }

    private static int bytesToInt(byte[] bytes) {
        return isEmpty(bytes) ? 0 : ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static byte[] encodeInt(int value) {
        return RLP.encodeElement(intToBytes(value));
    }

    private static int decodeInt(byte[] encoded) {
        return bytesToInt(encoded);
    }

//    @Override
//    public ECKey getKey() {
//        throw new UnsupportedOperationException("Cannot sign internal transaction.");
//    }
//
//    @Override
//    public void sign(byte[] privKeyBytes) throws ECKey.MissingPrivateKeyException {
//        throw new UnsupportedOperationException("Cannot sign internal transaction.");
//    }
//
//    @Override
//    public String toString() {
//        return "TransactionData [" +
//                "  parentHash=" + toHexString(getParentHash()) +
//                ", hash=" + toHexString(getHash()) +
//                ", nonce=" + toHexString(getNonce()) +
//                ", gasPrice=" + toHexString(getGasPrice()) +
//                ", gas=" + toHexString(getGasLimit()) +
//                ", sendAddress=" + toHexString(getSender()) +
//                ", receiveAddress=" + toHexString(getReceiveAddress()) +
//                ", value=" + toHexString(getValue()) +
//                ", data=" + toHexString(getData()) +
//                ", note=" + getNote() +
//                ", deep=" + getDeep() +
//                ", index=" + getIndex() +
//                ", rejected=" + isRejected() +
//                "]";
//    }
}
