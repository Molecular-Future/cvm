package org.mos.cvm.exec;

import java.math.BigInteger;

import org.apache.commons.codec.binary.Hex;
import org.mos.cvm.program.Storage;
import org.mos.mcore.bean.TransactionInfoWrapper;
import org.mos.mcore.concurrent.AccountInfoWrapper;

import com.google.protobuf.ByteString;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Data
@AllArgsConstructor
@Slf4j
public class TxStorage implements Storage {

	TransactionInfoWrapper txwrapper;

	@Override
	public BigInteger getBalance(byte[] address) throws Exception {
		log.debug("getBalance:" + Hex.encodeHexString(address));
		AccountInfoWrapper aiw = txwrapper.getAccount(ByteString.copyFrom(address));
		if (aiw != null) {
			return aiw.getBalance();
		}
		return BigInteger.ZERO;
	}

	@Override
	public byte[] getStorage(byte[] address, byte[] key) throws Exception {

		AccountInfoWrapper aiw = txwrapper.getAccount(ByteString.copyFrom(address));
		if (aiw != null) {
			byte bb[] = aiw.getStorage(key);
			if (bb != null) {
				log.debug("svmstorage getStorage ::" + Hex.encodeHexString(address) + ",key=" + Hex.encodeHexString(key)
						+ ",value=" + Hex.encodeHexString(bb));
			}else {
				log.debug("svmstorage getStorage ::" + Hex.encodeHexString(address) + ",key=" + Hex.encodeHexString(key)
				+ ",value=" + null);
			}
			return bb;
		}
		return null;
	}

	@Override
	public void putStorage(byte[] address, byte[] key, byte[] values) throws Exception {
		AccountInfoWrapper aiw = txwrapper.getAccount(ByteString.copyFrom(address));
		if (aiw != null) {
			log.debug("svmstorage putStorage ::" + Hex.encodeHexString(address) + ",key=" + Hex.encodeHexString(key)
					+ ",value=" + Hex.encodeHexString(values));

			aiw.putStorage(key, values);
		}
	}

}
