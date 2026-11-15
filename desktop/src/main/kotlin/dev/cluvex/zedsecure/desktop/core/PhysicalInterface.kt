package dev.cluvex.zedsecure.desktop.core

object PhysicalInterface {
    fun detect(os: Os = Os.current): String? = if (os == Os.WINDOWS) {
        runCatching { WinApi.bestInterfaceAlias(byteArrayOf(1, 1, 1, 1))?.takeIf { it != ZeptunTun.ADAPTER } }.getOrNull()
    } else null

    fun canBind(os: Os = Os.current, kernel: String = System.getProperty("os.version").orEmpty()): Boolean = os == Os.WINDOWS
}
