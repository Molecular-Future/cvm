package org.mos.cvm.program;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.mos.core.api.IAccountCVMHandler;
import org.mos.core.api.IAccountHandler;
import org.mos.core.cryptoapi.ICryptoHandler;
import org.mos.core.model.Account.AccountCryptoToken;
import org.mos.core.model.Account.AccountInfo.Builder;
import org.mos.core.model.Account.CryptoTokenOriginValue;
import org.mos.core.model.Account.TokenValue;
import org.mos.cvm.base.DataWord;
import org.mos.cvm.exec.invoke.ProgramInvoke;
import org.mos.cvm.exec.listener.ProgramListener;
import org.mos.cvm.exec.listener.ProgramListenerAware;

import com.google.protobuf.ByteString;

public class Storage implements IAccountCVMHandler, ProgramListenerAware {
	private IAccountCVMHandler repository;
	private DataWord address;
	private ProgramListener programListener;

	public Storage(ProgramInvoke programInvoke) {
		this.address = programInvoke.getOwnerAddress();
		this.repository = programInvoke.getRepository();
	}

	@Override
	public void setProgramListener(ProgramListener listener) {
		this.programListener = listener;
	}

	@Override
	public BigInteger addBalance(byte[] arg0, BigInteger arg1) throws Exception {
		return this.repository.addBalance(arg0, arg1);
	}

	@Override
	public void addCryptoTokenBalance(byte[] arg0, byte[] arg1, AccountCryptoToken arg2, long blockHeight) throws Exception {
		this.repository.addCryptoTokenBalance(arg0, arg1, arg2, blockHeight);
	}

	@Override
	public BigInteger addTokenBalance(byte[] arg0, byte[] arg1, BigInteger arg2) throws Exception {

		return this.repository.addTokenBalance(arg0, arg1, arg2);
	}

	@Override
	public Builder getAccount(byte[] arg0) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getAccount(arg0);
	}

	@Override
	public BigInteger getBalance(byte[] arg0) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getBalance(arg0);
	}

	@Override
	public ICryptoHandler getCrypto() {
		// TODO Auto-generated method stub
		return this.repository.getCrypto();
	}

	@Override
	public CryptoTokenOriginValue getCryptoToken(byte[] arg0) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getCryptoToken(arg0);
	}

	@Override
	public AccountCryptoToken getCryptoTokenBalance(byte[] arg0, byte[] arg1, byte[] arg2) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getCryptoTokenBalance(arg0, arg1, arg2);
	}

	@Override
	public byte[] getCryptoTokenBalanceByIndex(byte[] arg0, byte[] arg1, long arg2) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getCryptoTokenBalanceByIndex(arg0, arg1, arg2);
	}

	@Override
	public AccountCryptoToken getCryptoTokenByHash(byte[] arg0, byte[] arg1) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getCryptoTokenByHash(arg0, arg1);
	}

	@Override
	public byte[] getCryptoTokenByIndex(byte[] arg0, int arg1) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getCryptoTokenByIndex(arg0, arg1);
	}

	@Override
	public int getCryptoTokenSize(byte[] arg0, byte[] arg1) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getCryptoTokenSize(arg0, arg1);
	}

	@Override
	public Map<String, byte[]> getStorage(byte[] arg0, List<byte[]> arg1) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getStorage(arg0, arg1);
	}

	@Override
	public byte[] getStorage(byte[] arg0, byte[] arg1) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getStorage(arg0, arg1);
	}

	@Override
	public TokenValue getToken(byte[] arg0) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getToken(arg0);
	}

	@Override
	public BigInteger getTokenBalance(byte[] arg0, byte[] arg1) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.getTokenBalance(arg0, arg1);
	}

	@Override
	public boolean isContract(byte[] arg0) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.isContract(arg0);
	}

	@Override
	public boolean isExist(byte[] arg0) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.isExist(arg0);
	}

	@Override
	public void removeCryptoTokenBalance(byte[] arg0, byte[] arg1, byte[] arg2, long blockHeight) throws Exception {
		this.repository.removeCryptoTokenBalance(arg0, arg1, arg2, blockHeight);
	}

	@Override
	public void saveStorage(byte[] arg0, long blockHeight) throws Exception {
		this.repository.saveStorage(arg0, blockHeight);
	}
	

	@Override
	public void putStorage(byte[] arg0, byte[] arg1, byte[] arg2) throws Exception {
		this.repository.putStorage(arg0, arg1, arg2);
	}

	@Override
	public BigInteger subTokenBalance(byte[] arg0, byte[] arg1, BigInteger arg2) throws Exception {
		// TODO Auto-generated method stub
		return this.repository.subTokenBalance(arg0, arg1, arg2);
	}

	@Override
	public byte[] getContraceCode(byte[] arg0) throws Exception {
		return this.repository.getContraceCode(arg0);
	}

}
