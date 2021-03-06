
package org.mos.cvm.exec;

import org.mos.cvm.config.CVMConfig;
import org.mos.cvm.config.Constants;
import org.mos.cvm.exec.code.AbstractCodeRunner;
import org.mos.cvm.exec.code.CodeDefine;
import org.mos.cvm.program.Program;
import org.mos.cvm.program.Stack;
import org.spongycastle.util.encoders.Hex;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class BrewVM {

	private static final String logString = "BREWVM: {}    Op: [{}]  Gas: [{}] Deep: [{}]  Hint: [{}]";

	public static void step(Program program, int vmCounter) {
		try {
			OpCode op = OpCode.code(program.getCurrentOp());
			StringBuffer sb = null;
			if (CVMConfig.DEBUG_LOG_OPCODE) {
				 sb = new StringBuffer();
			}

			if (op == null) {
				log.info("unknow op code:" + Hex.toHexString(new byte[] { program.getCurrentOp() }));
				throw Program.Exception.invalidOpCode(program.getCurrentOp());
			} else {

				program.verifyStackSize(op.require());
				program.verifyStackOverflow(op.require(), op.ret());
				// long oldMemSize = program.getMemSize();
				Stack stack = program.getStack();
				AbstractCodeRunner cr = CodeDefine.runerMap[op.val() & 0xFF];

				if (cr != null) {
					cr.exec(program, stack, sb);
				} else {
					log.error("unknow cmd:" + op);
				}

				program.setPreviouslyExecutedOp(op.val());

				if (sb != null) {
					log.debug(logString, String.format("%5s", "[" + program.getPC() + "]"),
							String.format("%-12s", op.name()), 0, program.getCallDeep(), sb.toString());
				}

				// not enough
				if (vmCounter > 500000) {
					throw Program.Exception.notEnoughOpGas(op, 1000, 500000);
				}
			}
		} catch (RuntimeException e) {
			log.warn("VM halted: [{}]", e);
			program.resetFutureRefund();
			program.stop();
			throw e;
		} finally {
			// program.fullTrace();
		}
	}

	public static void play(Program program) {
		try {
			int vmCounter = 0;
			long start = System.currentTimeMillis();
			while (!program.isStopped()) {
				step(program, vmCounter++);
				if (vmCounter % 100 == 0) {
					if ((System.currentTimeMillis() - start) > Constants.MAX_EXEC_TIMEMS) {
						log.warn("VM halted for execute timeout:" + (System.currentTimeMillis() - start) + ",in "
								+ Constants.MAX_EXEC_TIMEMS);
						program.resetFutureRefund();
						program.stop();
						break;
					}
				}
			}
		} catch (RuntimeException e) {
			program.setRuntimeFailure(e);
		} catch (StackOverflowError soe) {
			log.error("\n !!! StackOverflowError: update your java run command with -Xss2M !!!\n", soe);
			System.exit(-1);
		} finally {
		}
	}

}
