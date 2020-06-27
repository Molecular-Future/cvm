package org.mos.cvm.config;

import onight.tfw.outils.conf.PropHelper;

public class CVMConfig {

	public static final PropHelper prop = new PropHelper(null);

	public static final boolean DEBUG_IGNORE_VERIFY_SIGN = prop.get("org.mos.cvm.ignore.verify.sign", "false")
			.equalsIgnoreCase("true");
	public static final boolean DEBUG_LOG_OPCODE = prop.get("org.mos.cvm.debug.log.opcode", "true")
			.equalsIgnoreCase("true");
	
}
