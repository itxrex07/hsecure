package dev.cluvex.zedsecure.desktop.core

import dev.cluvex.zedsecure.domain.config.OpenConnectProfile
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit

class DesktopOpenConnect(
    private val profile: OpenConnectProfile,
    private val workDir: File,
    private val askPassword: ((retry: Boolean) -> AdminAnswer?)? = null,
    private val os: Os = Os.current,
) {
    @Volatile private var windowsJob = false
    @Volatile private var helper: Process? = null
    @Volatile private var state: File? = null

    fun connect(): Result<Unit> {
        val binary = locate() ?: return Result.failure(IllegalStateException(missingMessage()))
        val dir = runCatching { Files.createTempDirectory(workDir.also { it.mkdirs() }.toPath(), "oc-").toFile() }.getOrNull() ?: return Result.failure(IllegalStateException("Could not create a private directory for OpenConnect"))
        state = dir
        val script = binary.script
        val args = runCatching { arguments(dir, script) }.getOrElse {
            discard()
            return Result.failure(it)
        }
        File(dir, SECRET).writeText(profile.password + "\n")
        val up = if (os == Os.WINDOWS) startWindows(dir, binary.executable, args) else false
        if (up) return Result.success(Unit)
        val reason = runCatching { File(dir, FAILED).readText().trim() }.getOrNull()?.takeIf { it.isNotEmpty() }
            ?: logTail(dir)
        disconnect()
        return Result.failure(IllegalStateException(reason ?: "OpenConnect could not connect"))
    }

    val isUp: Boolean
        get() = state?.let { File(it, READY).isFile } == true

    fun disconnect() {
        if (windowsJob) {
            windowsJob = false
            WindowsElevation.ocDown()
        }
        helper = null
        discard()
    }

    private fun discard() {
        val dir = state ?: return
        state = null
        runCatching { dir.deleteRecursively() }
    }

    internal fun arguments(dir: File, script: File?): List<String> = buildList {
        add("--protocol=${profile.protocol.ifBlank { OpenConnectProfile.PROTO_ANYCONNECT }}")
        if (profile.username.isNotBlank()) add("--user=${profile.username}")
        add("--passwd-on-stdin")
        add("--non-inter")
        if (profile.authgroup.isNotBlank()) add("--authgroup=${profile.authgroup}")
        if (profile.serverCertSha256.isNotBlank()) add("--servercert=${profile.serverCertSha256.trim()}")
        if (profile.caCertPem.isNotBlank()) add("--cafile=${write(dir, "ca.pem", profile.caCertPem).absolutePath}")
        when {
            profile.clientCertP12Base64.isNotBlank() -> {
                val p12 = File(dir, "client.p12").apply {
                    writeBytes(java.util.Base64.getMimeDecoder().decode(profile.clientCertP12Base64))
                }
                add("--certificate=${p12.absolutePath}")
            }
            profile.clientCertPem.isNotBlank() -> {
                add("--certificate=${write(dir, "client.pem", profile.clientCertPem).absolutePath}")
                if (profile.clientKeyPem.isNotBlank()) add("--sslkey=${write(dir, "client.key", profile.clientKeyPem).absolutePath}")
            }
        }
        if (profile.clientKeyPassword.isNotBlank()) add("--key-password=${profile.clientKeyPassword}")
        when (profile.tokenMode) {
            OpenConnectProfile.TOKEN_TOTP, OpenConnectProfile.TOKEN_HOTP, OpenConnectProfile.TOKEN_STOKEN -> {
                add("--token-mode=${profile.tokenMode}")
                if (profile.tokenSecret.isNotBlank()) add("--token-secret=@${write(dir, "token", profile.tokenSecret).absolutePath}")
            }
            OpenConnectProfile.TOKEN_OIDC -> throw IllegalStateException(
                "Single sign-on (OIDC) logins need a browser and are only available on Android for now",
            )
        }
        if (profile.userAgent.isNotBlank()) add("--useragent=${profile.userAgent}")
        desktopOs()?.let { add("--os=$it") }
        if (profile.disableDtls) add("--no-dtls")
        if (profile.mtu > 0) add("--mtu=${profile.mtu}")
        if (profile.proxy.isNotBlank()) add("--proxy=${profile.proxy}")
        if (os == Os.WINDOWS) add("--interface=$ADAPTER")
        script?.let { add("--script=${it.absolutePath}") }
        add(profile.server.trim())
    }

    private fun desktopOs(): String? = when (profile.reportedOs) {
        "", "android", "apple-ios" -> if (os == Os.WINDOWS) "win" else null
        else -> profile.reportedOs
    }
    private fun write(dir: File, name: String, text: String): File = File(dir, name).apply { writeText(text) }

    internal class Binary(val executable: File, val script: File?)

    private fun locate(): Binary? = if (os == Os.WINDOWS) {
        BundledTree.extract(File(workDir, "openconnect"), "openconnect")?.let { root ->
            File(root, "openconnect.exe").takeIf { it.isFile }?.let { Binary(it, File(root, "vpnc-script-win.js").takeIf { s -> s.isFile }) }
        }
    } else null
    private fun missingMessage(): String = "OpenConnect is not bundled with this Windows build"
    internal fun wrapScript(dir: File, real: File): File = File(dir, WRAPPER).apply {
        writeText(
            """
            |#!/bin/sh
            |${shQuote(real.absolutePath)} "${'$'}@"
            |rc=${'$'}?
            |[ "${'$'}{reason:-}" = connect ] && echo "${'$'}rc" > ${shQuote(File(dir, CONFIGURED).absolutePath)}
            |exit ${'$'}rc
            |""".trimMargin(),
        )
        setExecutable(true, true)
    }

    private fun startWindows(dir: File, executable: File, args: List<String>): Boolean {
        File(dir, "oc.args").writeText((listOf(executable.absolutePath) + args).joinToString("\n") + "\n")
        if (!WindowsElevation.ensure(workDir)) return false
        WindowsElevation.ocUp(dir).onFailure {
            println("[$LABEL] ${it.message}")
            File(dir, FAILED).writeText(it.message ?: "OpenConnect could not connect")
            return false
        }
        windowsJob = true
        return true
    }

    private fun awaitReady(dir: File, process: Process?): Boolean {
        val deadline = System.currentTimeMillis() + (CONNECT_WAIT_SEC + 15) * 1000
        while (System.currentTimeMillis() < deadline) {
            if (File(dir, READY).isFile) return true
            if (File(dir, FAILED).isFile) return false
            if (process != null && !process.isAlive && !File(dir, READY).isFile) return false
            Thread.sleep(POLL_MS)
        }
        return false
    }

    private fun logTail(dir: File): String? = runCatching {
        File(dir, LOG).readLines().filter { it.isNotBlank() }.takeLast(3).joinToString(" ")
    }.getOrNull()?.takeIf { it.isNotBlank() }

    companion object {
        const val ADAPTER = "ZedSecure OpenConnect"
        private const val LABEL = "openconnect"
        private const val SECRET = "secret"
        private const val LOG = "openconnect.log"
        private const val READY = "ready"
        private const val STOP = "stop"
        private const val FAILED = "failed"
        private const val CONFIGURED = "configured"
        private const val WRAPPER = "vpnc-wrap.sh"
        private const val SCRIPT_WAIT_SEC = 30L
        private const val CONNECT_WAIT_SEC = 90L
        private const val STOP_WAIT_SEC = 12L
        private const val POLL_MS = 250L
        internal const val CONNECTED = "Connected as |Configured as |ESP session established|Established DTLS connection"


        internal fun shQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

        internal fun winArg(value: String): String {
            if (value.isNotEmpty() && value.none { it == ' ' || it == '\t' || it == '"' }) return value
            val out = StringBuilder("\"")
            var slashes = 0
            for (c in value) {
                when (c) {
                    '\\' -> slashes++
                    '"' -> {
                        repeat(slashes * 2 + 1) { out.append('\\') }
                        out.append('"')
                        slashes = 0
                    }
                    else -> {
                        repeat(slashes) { out.append('\\') }
                        out.append(c)
                        slashes = 0
                    }
                }
            }
            repeat(slashes * 2) { out.append('\\') }
            return out.append('"').toString()
        }
    }
}
