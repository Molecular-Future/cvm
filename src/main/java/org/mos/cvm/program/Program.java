package org.mos.cvm.program;

import static java.lang.StrictMath.min;
import static java.lang.String.format;
import static org.apache.commons.lang3.ArrayUtils.getLength;
import static org.apache.commons.lang3.ArrayUtils.isEmpty;
import static org.apache.commons.lang3.ArrayUtils.nullToEmpty;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.BitSet;
import java.util.NavigableSet;
import java.util.TreeSet;

import org.apache.commons.lang3.tuple.Pair;
import org.mos.cvm.base.DataWord;
import org.mos.cvm.exec.BrewVM;
import org.mos.cvm.exec.CRC20Contract;
import org.mos.cvm.exec.CRC21Contract;
import org.mos.cvm.exec.CVMAccountWrapper;
import org.mos.cvm.exec.OpCode;
import org.mos.cvm.exec.PrecompiledContracts.PrecompiledContract;
import org.mos.cvm.exec.invoke.ProgramInvokerInfo;
import org.mos.cvm.model.Cvm.CVMContract;
import org.mos.cvm.utils.Utils;
import org.mos.mcore.actuators.tokens.impl20.RC20AccountWrapper;
import org.mos.mcore.actuators.tokens.impl721.RC721AccountWrapper;
import org.mos.mcore.concurrent.AccountInfoWrapper;
import org.mos.mcore.handler.MCoreServices;
import org.mos.mcore.model.Account.AccountInfo;
import org.mos.mcore.model.Account.AccountInfo.AccountType;
import org.spongycastle.util.encoders.Hex;

import com.google.protobuf.ByteString;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import onight.tfw.outils.conf.PropHelper;

@Slf4j
@Data
public class Program {

	private static final int MAX_DEPTH = 1024;

	private static final int MAX_STACKSIZE = 1024;

	ProgramInvokerInfo invokeInfo;

	private CVMAccountWrapper contractAccount;

	private Stack stack;
	private Memory memory;
	private Storage storage;
	private int pc;
	private byte previouslyExecutedOp;
	private boolean stopped;

	MCoreServices mcore;

	byte returnDataBuffer[];
	byte[] ops;

	public Program(CVMAccountWrapper contractAccount, MCoreServices mcore, ProgramInvokerInfo invokeInfo,
			Storage storage) {
		this.contractAccount = contractAccount;
		this.mcore = mcore;
		this.invokeInfo = invokeInfo;
		this.memory = new Memory();
		this.stack = new Stack();

		this.pc = 0;
		if (contractAccount.getCompiledProgram() != null) {
			this.ops = contractAccount.getCompiledProgram().getOps();
		}
		this.storage = storage;
	}

	static PropHelper props = new PropHelper(null);

	public AccountInfoWrapper getProgramContractAccount(DataWord codeAddr) {
		ByteString code_addr_BS = ByteString.copyFrom(codeAddr.getLast20Bytes());
		AccountInfoWrapper existContract = invokeInfo.getTxw().getBlockContext().getAccounts().get(code_addr_BS);
		if (existContract == null) {
			synchronized (invokeInfo.getTxw().getBlockContext().getAccounts()) {
				existContract = invokeInfo.getTxw().getBlockContext().getAccounts().get(code_addr_BS);
				if (existContract == null || !(existContract instanceof CVMAccountWrapper)) {
					AccountInfo.Builder account = mcore.getAccountHandler().getAccount(code_addr_BS);
					if (account == null) {
						return null;
					}

					if (account.getType() == AccountType.RC20_CONTRACT) {
						if (existContract != null) {
							return existContract;
						} else {
							existContract = new RC20AccountWrapper(account);
//							existContract.loadStorageTrie(mcore.getStateTrie());
						}
					} else if (account.getType() == AccountType.RC721_CONTRACT) {
						if (existContract != null) {
							return existContract;
						} else {
							existContract = new RC721AccountWrapper(account);
//							existContract.loadStorageTrie(mcore.getStateTrie());
						}
					} else {
						existContract = new CVMAccountWrapper(account);
						existContract.loadStorageTrie(mcore.getStateTrie());
					}
					invokeInfo.getTxw().getBlockContext().getAccounts().put(code_addr_BS, existContract);
				}
			}
		}
		return existContract;

	}

	public int getCallDeep() {
		return invokeInfo.getCallDeep();
	}

	public byte getOp(int pc) {
		return (getLength(ops) <= pc) ? 0 : ops[pc];
	}

	public byte getCurrentOp() {
		return isEmpty(ops) ? 0 : ops[pc];
	}

	/**
	 * Should be set only after the OP is fully executed.
	 */
	public void setPreviouslyExecutedOp(byte op) {
		this.previouslyExecutedOp = op;
	}

	/**
	 * Returns the last fully executed OP.
	 */
	public byte getPreviouslyExecutedOp() {
		return this.previouslyExecutedOp;
	}

	public void stackPush(byte[] data) {
		stackPush(new DataWord(data));
	}

	public void stackPushZero() {
		stackPush(new DataWord(0));
	}

	public void stackPushOne() {
		DataWord stackWord = new DataWord(1);
		stackPush(stackWord);
	}

	public void stackPush(DataWord stackWord) {
		verifyStackOverflow(0, 1); // Sanity Check
		stack.push(stackWord);
	}

	public Stack getStack() {
		return this.stack;
	}

	public int getPC() {
		return pc;
	}

	public void setPC(DataWord pc) {
		this.setPC(pc.intValue());
	}

	public void setPC(int pc) {
		this.pc = pc;

		if (this.pc >= ops.length) {
			stop();
		}
	}

	public boolean isStopped() {
		return stopped;
	}

	public void stop() {
		stopped = true;
	}

	public void setHReturn(byte[] buff) {
		getResult().setHReturn(buff);
	}

	public void step() {
		setPC(pc + 1);
	}

	public byte[] sweep(int n) {

		if (pc + n > ops.length)
			stop();

		byte[] data = Arrays.copyOfRange(ops, pc, pc + n);
		pc += n;
		if (pc >= ops.length)
			stop();

		return data;
	}

	public DataWord stackPop() {
		return stack.pop();
	}

	/**
	 * Verifies that the stack is at least <code>stackSize</code>
	 *
	 * @param stackSize
	 *            int
	 * @throws StackTooSmallException
	 *             If the stack is smaller than <code>stackSize</code>
	 */
	public void verifyStackSize(int stackSize) {
		if (stack.size() < stackSize) {
			throw Program.Exception.tooSmallStack(stackSize, stack.size());
		}
	}

	public void verifyStackOverflow(int argsReqs, int returnReqs) {
		if ((stack.size() - argsReqs + returnReqs) > MAX_STACKSIZE) {
			throw new StackTooLargeException("Expected: overflow " + MAX_STACKSIZE + " elements stack limit");
		}
	}

	public int getMemSize() {
		return memory.size();
	}

	public void memorySave(DataWord addrB, DataWord value) {
		memory.write(addrB.intValue(), value.getData(), value.getData().length, false);
	}

	public void memorySaveLimited(int addr, byte[] data, int dataSize) {
		memory.write(addr, data, dataSize, true);
	}

	public void memorySave(int addr, byte[] value) {
		memory.write(addr, value, value.length, false);
	}

	public void memoryExpand(DataWord outDataOffs, DataWord outDataSize) {
		if (!outDataSize.isZero()) {
			memory.extend(outDataOffs.intValue(), outDataSize.intValue());
		}
	}

	public void memorySave(int addr, int allocSize, byte[] value) {
		memory.extendAndWrite(addr, allocSize, value);
	}

	public DataWord memoryLoad(DataWord addr) {
		return memory.readWord(addr.intValue());
	}

	public DataWord memoryLoad(int address) {
		return memory.readWord(address);
	}

	public byte[] memoryChunk(int offset, int size) {
		return memory.read(offset, size);
	}

	public void allocateMemory(int offset, int size) {
		memory.extend(offset, size);
	}

	public void callToAddress(OpCode type, DataWord codeAddress, DataWord inDataOffs, DataWord inDataSize,
			DataWord outDataOffs, DataWord outDataSize) {
		returnDataBuffer = null; // reset return buffer right before the call

		if (getCallDeep() == MAX_DEPTH) {
			stackPushZero();
			return;
		}

		byte[] data = memoryChunk(inDataOffs.intValue(), inDataSize.intValue());
		ProgramResult result = null;

		AccountInfoWrapper nextcontractAccount = getProgramContractAccount(codeAddress);
		if (nextcontractAccount != null && nextcontractAccount instanceof CVMAccountWrapper) {
			CVMAccountWrapper cvmAccount = (CVMAccountWrapper) nextcontractAccount;
			cvmAccount.loadStorageTrie(mcore.getStateTrie());
			ProgramInvokerInfo nextprogramInvoke = new ProgramInvokerInfo(invokeInfo.getContractAccount(),
					invokeInfo.getTxw(), cvmAccount, data, invokeInfo.getBlockInfo(), invokeInfo.getCallDeep() + 1);

			Program program = new Program(cvmAccount, mcore, nextprogramInvoke, storage);
			BrewVM.play(program);
			result = program.getResult();

			// getResult().merge(result);gas....值

			if (result.getException() != null || result.isRevert()) {
				stackPushZero();
				if (result.getException() != null) {
					return;
				}
			} else {
				stackPushOne();
			}
		} else if (nextcontractAccount != null && nextcontractAccount instanceof RC20AccountWrapper) {
			CRC20Contract contract = new CRC20Contract(mcore, invokeInfo, (RC20AccountWrapper) nextcontractAccount);
			callToPrecompiledAddress(inDataOffs, inDataSize, outDataOffs, outDataSize, contract);
			return;
		} else if (nextcontractAccount != null && nextcontractAccount instanceof RC721AccountWrapper) {
			CRC21Contract contract = new CRC21Contract(mcore, invokeInfo, (RC721AccountWrapper) nextcontractAccount);
			callToPrecompiledAddress(inDataOffs, inDataSize, outDataOffs, outDataSize, contract);
			return;

		} else {
			stackPushOne();
		}
		if (result != null) {
			byte[] buffer = result.getHReturn();
			int offset = outDataOffs.intValue();
			int size = outDataSize.intValue();
			memorySaveLimited(offset, buffer, size);
			returnDataBuffer = buffer;
		}

	}

	public void resetFutureRefund() {
		getResult().resetFutureRefund();
	}

	public void storageSave(DataWord word1, DataWord word2) {
		storageSave(word1.getData(), word2.getData());
	}

	public void storageSave(byte[] key, byte[] val) {
		try {
			getStorage().putStorage(getOwnerAddress().getNoLeadZeroesData(), key, val);
		} catch (java.lang.Exception e) {
			e.printStackTrace();
		}
	}

	public byte[] getCodeAt(DataWord address) {

		AccountInfo.Builder account = null;
		try {
			account = mcore.getAccountHandler().getAccount(address.getLast20Bytes());
		} catch (java.lang.Exception e) {
			log.debug("cannot getCodeAt account:" + address.shortHex() + ":" + e.getMessage());
		}
		byte[] code = null;
		if (account != null && account.getExtData() != null) {
			if (account.getType() == AccountType.CVM_CONTRACT) {
				try {
					code = CVMContract.parseFrom(account.getExtData()).getDatas().toByteArray();
				} catch (Throwable e1) {
					log.warn("error in parse contract ", e1);
				} // invokeInfo.getRepository().getCode(address.getLast20Bytes());
				return nullToEmpty(code);
			} else if (account.getType() == AccountType.RC20_CONTRACT) {
				return address.getData();
			} else if (account.getType() == AccountType.RC721_CONTRACT) {
				return address.getData();
			} else {
				return nullToEmpty(code);
			}
		} else {
			return nullToEmpty(code);
		}
	}

	public DataWord getOwnerAddress() {
		return invokeInfo.getOwnerAddress().clone();
	}

	public DataWord getBlockHash(int index) {
		return this.getPrevHash();
	}

	public DataWord getBalance(DataWord address) {
		BigInteger balance = BigInteger.ZERO;
		try {
			balance = getStorage().getBalance(address.getNoLeadZeroesData());
		} catch (java.lang.Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new DataWord(balance.toByteArray());
	}

	public DataWord getOriginAddress() {
		return invokeInfo.getOriginAddress().clone();
	}

	public DataWord getCallerAddress() {
		return invokeInfo.getCallerAddress().clone();
	}

	public DataWord getCallValue() {
		return invokeInfo.getCallValue().clone();
	}

	public DataWord getDataSize() {
		return invokeInfo.getDataSize().clone();
	}

	public DataWord getDataValue(DataWord index) {
		return invokeInfo.getDataValue(index);
	}

	public byte[] getDataCopy(DataWord offset, DataWord length) {
		return invokeInfo.getDataCopy(offset, length);
	}

	public DataWord getReturnDataBufferSize() {
		return new DataWord(getReturnDataBufferSizeI());
	}

	private int getReturnDataBufferSizeI() {
		return returnDataBuffer == null ? 0 : returnDataBuffer.length;
	}

	public byte[] getReturnDataBufferData(DataWord off, DataWord size) {
		if ((long) off.intValueSafe() + size.intValueSafe() > getReturnDataBufferSizeI())
			return null;
		return returnDataBuffer == null ? new byte[0]
				: Arrays.copyOfRange(returnDataBuffer, off.intValueSafe(), off.intValueSafe() + size.intValueSafe());
	}

	public DataWord storageLoad(DataWord key) {
		DataWord ret;
		try {
			ret = new DataWord(getStorage().getStorage(getOwnerAddress().getNoLeadZeroesData(), key.getData()));
			return ret == null ? null : ret.clone();
		} catch (java.lang.Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public DataWord getPrevHash() {
		return invokeInfo.getBlockInfo().getPrevHash().clone();
	}

	public DataWord getCoinbase() {
		return invokeInfo.getBlockInfo().getCoinbase().clone();
	}

	public DataWord getTimestamp() {
		return invokeInfo.getBlockInfo().getTimestamp().clone();
	}

	public DataWord getNumber() {
		return invokeInfo.getBlockInfo().getNumber().clone();
	}

	public ProgramResult getResult() {
		return invokeInfo.getResult();
	}

	public void setRuntimeFailure(RuntimeException e) {
		getResult().setException(e);
	}

	public String memoryToString() {
		return memory.toString();
	}

	static String formatBinData(byte[] binData, int startPC) {
		StringBuilder ret = new StringBuilder();
		for (int i = 0; i < binData.length; i += 16) {
			ret.append(Utils.align("" + Integer.toHexString(startPC + (i)) + ":", ' ', 8, false));
			ret.append(Hex.toHexString(binData, i, min(16, binData.length - i))).append('\n');
		}
		return ret.toString();
	}

	public static String stringifyMultiline(byte[] code) {
		int index = 0;
		StringBuilder sb = new StringBuilder();
		BitSet mask = buildReachableBytecodesMask(code);
		ByteArrayOutputStream binData = new ByteArrayOutputStream();
		int binDataStartPC = -1;

		while (index < code.length) {
			final byte opCode = code[index];
			OpCode op = OpCode.code(opCode);

			if (!mask.get(index)) {
				if (binDataStartPC == -1) {
					binDataStartPC = index;
				}
				binData.write(code[index]);
				index++;
				if (index < code.length)
					continue;
			}

			if (binDataStartPC != -1) {
				sb.append(formatBinData(binData.toByteArray(), binDataStartPC));
				binDataStartPC = -1;
				binData = new ByteArrayOutputStream();
				if (index == code.length)
					continue;
			}

			sb.append(Utils.align("" + Integer.toHexString(index) + ":", ' ', 8, false));

			if (op == null) {
				sb.append("<UNKNOWN>: ").append(0xFF & opCode).append("\n");
				index++;
				continue;
			}

			if (op.name().startsWith("PUSH")) {
				sb.append(' ').append(op.name()).append(' ');

				int nPush = op.val() - OpCode.PUSH1.val() + 1;
				byte[] data = Arrays.copyOfRange(code, index + 1, index + nPush + 1);
				BigInteger bi = new BigInteger(1, data);
				sb.append("0x").append(bi.toString(16));
				if (bi.bitLength() <= 32) {
					sb.append(" (").append(new BigInteger(1, data).toString()).append(") ");
				}

				index += nPush + 1;
			} else {
				sb.append(' ').append(op.name());
				index++;
			}
			sb.append('\n');
		}

		return sb.toString();
	}

	static class ByteCodeIterator {
		byte[] code;
		int pc;

		public ByteCodeIterator(byte[] code) {
			this.code = code;
		}

		public void setPC(int pc) {
			this.pc = pc;
		}

		public int getPC() {
			return pc;
		}

		public OpCode getCurOpcode() {
			return pc < code.length ? OpCode.code(code[pc]) : null;
		}

		public boolean isPush() {
			return getCurOpcode() != null ? getCurOpcode().name().startsWith("PUSH") : false;
		}

		public byte[] getCurOpcodeArg() {
			if (isPush()) {
				int nPush = getCurOpcode().val() - OpCode.PUSH1.val() + 1;
				byte[] data = Arrays.copyOfRange(code, pc + 1, pc + nPush + 1);
				return data;
			} else {
				return new byte[0];
			}
		}

		public boolean next() {
			pc += 1 + getCurOpcodeArg().length;
			return pc < code.length;
		}
	}

	static BitSet buildReachableBytecodesMask(byte[] code) {
		NavigableSet<Integer> gotos = new TreeSet<>();
		ByteCodeIterator it = new ByteCodeIterator(code);
		BitSet ret = new BitSet(code.length);
		int lastPush = 0;
		int lastPushPC = 0;
		do {
			ret.set(it.getPC()); // reachable bytecode
			if (it.isPush()) {
				lastPush = new BigInteger(1, it.getCurOpcodeArg()).intValue();
				lastPushPC = it.getPC();
			}
			if (it.getCurOpcode() == OpCode.JUMP || it.getCurOpcode() == OpCode.JUMPI) {
				if (it.getPC() != lastPushPC + 1) {
					// some PC arithmetic we totally can't deal with
					// assuming all bytecodes are reachable as a fallback
					ret.set(0, code.length);
					return ret;
				}
				int jumpPC = lastPush;
				if (!ret.get(jumpPC)) {
					// code was not explored yet
					gotos.add(jumpPC);
				}
			}
			if (it.getCurOpcode() == OpCode.JUMP || it.getCurOpcode() == OpCode.RETURN
					|| it.getCurOpcode() == OpCode.STOP) {
				if (gotos.isEmpty())
					break;
				it.setPC(gotos.pollFirst());
			}
		} while (it.next());
		return ret;
	}

	public static String stringify(byte[] code) {
		int index = 0;
		StringBuilder sb = new StringBuilder();

		while (index < code.length) {
			final byte opCode = code[index];
			OpCode op = OpCode.code(opCode);

			if (op == null) {
				sb.append(" <UNKNOWN>: ").append(0xFF & opCode).append(" ");
				index++;
				continue;
			}

			if (op.name().startsWith("PUSH")) {
				sb.append(' ').append(op.name()).append(' ');

				int nPush = op.val() - OpCode.PUSH1.val() + 1;
				byte[] data = Arrays.copyOfRange(code, index + 1, index + nPush + 1);
				BigInteger bi = new BigInteger(1, data);
				sb.append("0x").append(bi.toString(16)).append(" ");

				index += nPush + 1;
			} else {
				sb.append(' ').append(op.name());
				index++;
			}
		}

		return sb.toString();
	}

	public int verifyJumpDest(DataWord nextPC) {
		if (nextPC.bytesOccupied() > 4) {
			throw Program.Exception.badJumpDestination(-1);
		}
		int ret = nextPC.intValue();
		if (!contractAccount.getCompiledProgram().hasJumpDest(ret)) {
			throw Program.Exception.badJumpDestination(ret);
		}
		return ret;
	}

	public void callToPrecompiledAddress(DataWord inDataOffs, DataWord inDataSize, DataWord outDataOffs,
			DataWord outDataSize, PrecompiledContract contract

	) {
		returnDataBuffer = null; // reset return buffer right before the call

		if (getCallDeep() == MAX_DEPTH) {
			stackPushZero();
			return;
		}

		byte[] data = this.memoryChunk(inDataOffs.intValue(), inDataSize.intValue());

		Pair<Boolean, byte[]> out = contract.execute(data);

		if (out.getLeft()) { // success
			this.stackPushOne();
			returnDataBuffer = out.getRight();
		} else {
			this.stackPushZero();
			this.setStopped(true);
		}

		this.memorySave(outDataOffs.intValue(), out.getRight());
	}

	public interface ProgramOutListener {
		void output(String out);
	}

	/**
	 * Denotes problem when executing Ethereum bytecode. From blockchain and peer
	 * perspective this is quite normal situation and doesn't mean exceptional
	 * situation in terms of the program execution
	 */
	@SuppressWarnings("serial")
	public static class BytecodeExecutionException extends RuntimeException {
		public BytecodeExecutionException(String message) {
			super(message);
		}
	}

	@SuppressWarnings("serial")
	public static class OutOfGasException extends BytecodeExecutionException {

		public OutOfGasException(String message, Object... args) {
			super(format(message, args));
		}
	}

	@SuppressWarnings("serial")
	public static class IllegalOperationException extends BytecodeExecutionException {

		public IllegalOperationException(String message, Object... args) {
			super(format(message, args));
		}
	}

	@SuppressWarnings("serial")
	public static class BadJumpDestinationException extends BytecodeExecutionException {

		public BadJumpDestinationException(String message, Object... args) {
			super(format(message, args));
		}
	}

	@SuppressWarnings("serial")
	public static class StackTooSmallException extends BytecodeExecutionException {

		public StackTooSmallException(String message, Object... args) {
			super(format(message, args));
		}
	}

	@SuppressWarnings("serial")
	public static class ReturnDataCopyIllegalBoundsException extends BytecodeExecutionException {
		public ReturnDataCopyIllegalBoundsException(DataWord off, DataWord size, long returnDataSize) {
			super(String.format("Illegal RETURNDATACOPY arguments: offset (%s) + size (%s) > RETURNDATASIZE (%d)", off,
					size, returnDataSize));
		}
	}

	@SuppressWarnings("serial")
	public static class StaticCallModificationException extends BytecodeExecutionException {
		public StaticCallModificationException() {
			super("Attempt to call a state modifying opcode inside STATICCALL");
		}
	}

	public static class Exception {

		public static OutOfGasException notEnoughOpGas(OpCode op, long opGas, long programGas) {
			return new OutOfGasException("Not enough gas for '%s' operation executing: opGas[%d], programGas[%d];", op,
					opGas, programGas);
		}

		public static OutOfGasException notEnoughOpGas(OpCode op, DataWord opGas, DataWord programGas) {
			return notEnoughOpGas(op, opGas.longValue(), programGas.longValue());
		}

		public static OutOfGasException notEnoughOpGas(OpCode op, BigInteger opGas, BigInteger programGas) {
			return notEnoughOpGas(op, opGas.longValue(), programGas.longValue());
		}

		public static OutOfGasException gasOverflow(BigInteger actualGas, BigInteger gasLimit) {
			return new OutOfGasException("Gas value overflow: actualGas[%d], gasLimit[%d];", actualGas.longValue(),
					gasLimit.longValue());
		}

		public static IllegalOperationException invalidOpCode(byte... opCode) {
			return new IllegalOperationException("Invalid operation code: opCode[%s];", Hex.toHexString(opCode, 0, 1));
		}

		public static BadJumpDestinationException badJumpDestination(int pc) {
			return new BadJumpDestinationException("Operation with pc isn't 'JUMPDEST': PC[%d];", pc);
		}

		public static StackTooSmallException tooSmallStack(int expectedSize, int actualSize) {
			return new StackTooSmallException("Expected stack size %d but actual %d;", expectedSize, actualSize);
		}
	}

	@SuppressWarnings("serial")
	public class StackTooLargeException extends BytecodeExecutionException {
		public StackTooLargeException(String message) {
			super(message);
		}
	}

	/**
	 * used mostly for testing reasons
	 */
	public byte[] getMemory() {
		return memory.read(0, memory.size());
	}

	/**
	 * used mostly for testing reasons
	 */
	public void initMem(byte[] data) {
		this.memory.write(0, data, data.length, false);
	}
}
