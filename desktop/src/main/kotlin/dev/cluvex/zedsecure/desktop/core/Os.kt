package dev.cluvex.zedsecure.desktop.core

enum class Os { WINDOWS, OTHER;
    companion object {
        val current: Os by lazy {
            if (System.getProperty("os.name")?.lowercase().orEmpty().contains("win")) WINDOWS else OTHER
        }
    }
}

internal fun exec(vararg cmd: String, timeoutSec: Long = 30): Pair<Int, String> {
    return try {
        val p = ProcessBuilder(*cmd).redirectErrorStream(true).start()
        val out = p.inputStream.bufferedReader().readText()
        val done = p.waitFor(timeoutSec, java.util.concurrent.TimeUnit.SECONDS)
        if (!done) { p.destroyForcibly(); return -1 to out }
        p.exitValue() to out
    } catch (e: Exception) {
        -1 to (e.message ?: "exec failed")
    }
}
