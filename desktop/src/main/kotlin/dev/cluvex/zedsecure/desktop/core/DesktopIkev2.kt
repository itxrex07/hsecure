package dev.cluvex.zedsecure.desktop.core

import dev.cluvex.zedsecure.domain.config.Ikev2Auth
import dev.cluvex.zedsecure.domain.config.Ikev2Profile
import java.io.File
import java.util.Base64
import java.util.UUID

class DesktopIkev2(
    private val profile: Ikev2Profile,
    private val workDir: File,
    private val os: Os = Os.current,
) {
    fun connect(): Result<Unit> {
        if (profile.server.isBlank()) return fail("The IKEv2 profile has no server")
        return when (profile.effectiveAuth) {
            Ikev2Auth.CERTIFICATE, Ikev2Auth.EAP_TLS ->
                fail("Certificate sign-in lives in Android's key store; use a username and password or a pre-shared key on the desktop")
            else -> if (os == Os.WINDOWS) windows() else fail("IKEv2 is not available on this system")
        }
    }

    fun disconnect() {
        if (os == Os.WINDOWS) exec("rasdial", NAME, "/disconnect", timeoutSec = 20)
    }
    fun isUp(): Boolean = os == Os.WINDOWS && exec("rasdial", timeoutSec = 10).second.lineSequence().any { it.trim() == NAME }

    private fun windows(): Result<Unit> {
        if (profile.effectiveAuth == Ikev2Auth.PSK) {
            return fail("Windows signs in to IKEv2 with a username and password, not a pre-shared key")
        }
        val dir = workDir.also { it.mkdirs() }
        val ca = caFile(dir, "ikev2-ca.cer", der = true)
        val marker = File(dir, "ikev2-ca.trusted")
        val thumbprint = ca?.let { sha1Hex(it.readBytes()) }
        if (ca != null && runCatching { marker.readText().trim() }.getOrNull() != thumbprint) {
            if (!WindowsElevation.ensure(dir)) return fail("Administrator rights are needed to trust the server's CA certificate")
            WindowsElevation.trustCa(ca).onFailure { return fail("Windows did not add the server's CA certificate: ${it.message}") }
            thumbprint?.let { marker.writeText(it) }
        }
        val result = execWithEnv(
            listOf("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "-"),
            mapOf(
                "ZS_NAME" to NAME,
                "ZS_SERVER" to profile.server.trim(),
                "ZS_USER" to profile.username,
                "ZS_PASS" to profile.plainPassword(),
            ),
            timeoutSec = 120,
            input = windowsScript(),
        )
        if (result.first == 0) return Result.success(Unit)
        return fail(windowsError(result.first, result.second))
    }

    internal fun windowsScript(): String {
        val ike = proposal(profile.ikeProposal)
        val esp = proposal(profile.espProposal.ifBlank { profile.ikeProposal })
        return """
            |& {
            |  ${'$'}ErrorActionPreference = 'Stop'
            |  ${'$'}name = ${'$'}env:ZS_NAME
            |  if (Get-VpnConnection -Name ${'$'}name -ErrorAction SilentlyContinue) {
            |    rasdial ${'$'}name /disconnect | Out-Null
            |    Remove-VpnConnection -Name ${'$'}name -Force
            |  }
            |  Add-VpnConnection -Name ${'$'}name -ServerAddress ${'$'}env:ZS_SERVER -TunnelType Ikev2 -EncryptionLevel Required -AuthenticationMethod Eap -RememberCredential -Force
            |  Set-VpnConnectionIPsecConfiguration -ConnectionName ${'$'}name -AuthenticationTransformConstants ${esp.windowsAuth} -CipherTransformConstants ${esp.windowsEspCipher} -EncryptionMethod ${ike.windowsCipher} -IntegrityCheckMethod ${ike.windowsIntegrity} -DHGroup ${ike.windowsDh} -PfsGroup None -Force
            |  ${'$'}ErrorActionPreference = 'Continue'
            |  rasdial ${'$'}name ${'$'}env:ZS_USER ${'$'}env:ZS_PASS
            |  exit ${'$'}LASTEXITCODE
            |}
            """.trimMargin() + "\n\n"
    }

    private fun windowsError(code: Int, output: String): String = when (code) {
        691 -> "The server refused the username or password"
        809 -> "The server did not answer on UDP 500 and 4500"
        13801 -> "Windows does not trust the server's certificate; add its CA certificate to the profile"
        13806, 13832 -> "The server's certificate does not match its address or remote ID"
        13868 -> "The server refused Windows' encryption settings; set the IKE and ESP proposals in the profile"
        else -> "IKEv2 failed (rasdial $code): " + output.lineSequence().map { it.trim() }.lastOrNull { it.isNotEmpty() }.orEmpty()
    }

    internal fun macProfile(): String {
        val psk = profile.effectiveAuth == Ikev2Auth.PSK
        val ike = proposal(profile.ikeProposal)
        val esp = proposal(profile.espProposal.ifBlank { profile.ikeProposal })
        val ca = pemBody(profile.caCertPem)
        fun x(value: String) = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        fun sa(p: Proposal) = """
            |<dict>
            |<key>EncryptionAlgorithm</key><string>${p.appleCipher}</string>
            |<key>IntegrityAlgorithm</key><string>${p.appleIntegrity}</string>
            |<key>DiffieHellmanGroup</key><integer>${p.appleDh}</integer>
            |</dict>""".trimMargin()
        val caPayload = ca?.let {
            """
            |<dict>
            |<key>PayloadType</key><string>com.apple.security.root</string>
            |<key>PayloadIdentifier</key><string>$PAYLOAD_ID.ca</string>
            |<key>PayloadUUID</key><string>${UUID.randomUUID()}</string>
            |<key>PayloadVersion</key><integer>1</integer>
            |<key>PayloadDisplayName</key><string>ZedSecure IKEv2 CA</string>
            |<key>PayloadContent</key><data>$it</data>
            |</dict>""".trimMargin()
        }.orEmpty()
        val auth = if (psk) {
            "<key>AuthenticationMethod</key><string>SharedSecret</string>\n<key>SharedSecret</key><string>${x(profile.plainPsk())}</string>"
        } else {
            "<key>AuthenticationMethod</key><string>None</string>\n<key>ExtendedAuthEnabled</key><integer>1</integer>\n" +
                "<key>AuthName</key><string>${x(profile.username)}</string>\n<key>AuthPassword</key><string>${x(profile.plainPassword())}</string>"
        }
        return """
            |<?xml version="1.0" encoding="UTF-8"?>
            |<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            |<plist version="1.0">
            |<dict>
            |<key>PayloadContent</key>
            |<array>
            |$caPayload
            |<dict>
            |<key>PayloadType</key><string>com.apple.vpn.managed</string>
            |<key>PayloadIdentifier</key><string>$PAYLOAD_ID.vpn</string>
            |<key>PayloadUUID</key><string>${UUID.randomUUID()}</string>
            |<key>PayloadVersion</key><integer>1</integer>
            |<key>PayloadDisplayName</key><string>$NAME</string>
            |<key>UserDefinedName</key><string>$NAME</string>
            |<key>VPNType</key><string>IKEv2</string>
            |<key>IKEv2</key>
            |<dict>
            |<key>RemoteAddress</key><string>${x(profile.server.trim())}</string>
            |<key>RemoteIdentifier</key><string>${x(profile.effectiveRemoteId.trim())}</string>
            |<key>LocalIdentifier</key><string>${x(profile.localId.ifBlank { profile.username }.trim())}</string>
            |$auth
            |<key>IKESecurityAssociationParameters</key>
            |${sa(ike)}
            |<key>ChildSecurityAssociationParameters</key>
            |${sa(esp)}
            |</dict>
            |</dict>
            |</array>
            |<key>PayloadType</key><string>Configuration</string>
            |<key>PayloadIdentifier</key><string>$PAYLOAD_ID</string>
            |<key>PayloadUUID</key><string>${UUID.randomUUID()}</string>
            |<key>PayloadVersion</key><integer>1</integer>
            |<key>PayloadDisplayName</key><string>$NAME</string>
            |</dict>
            |</plist>
            """.trimMargin() + "\n"
    }

    private fun caFile(dir: File, name: String, der: Boolean): File? {
        val body = pemBody(profile.caCertPem) ?: return null
        return File(dir, name).apply {
            if (der) writeBytes(Base64.getMimeDecoder().decode(body))
            else writeText("-----BEGIN CERTIFICATE-----\n$body\n-----END CERTIFICATE-----\n")
        }
    }

    private fun sha1Hex(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-1").digest(bytes).joinToString("") { "%02X".format(it) }

    private fun pemBody(pem: String): String? = pem
        .substringAfter("-----BEGIN CERTIFICATE-----", "")
        .substringBefore("-----END CERTIFICATE-----")
        .filterNot { it.isWhitespace() }
        .takeIf { it.isNotEmpty() }

    internal data class Proposal(
        val windowsCipher: String,
        val windowsEspCipher: String,
        val windowsIntegrity: String,
        val windowsAuth: String,
        val windowsDh: String,
        val appleCipher: String,
        val appleIntegrity: String,
        val appleDh: Int,
    )

    internal fun proposal(raw: String): Proposal {
        val p = raw.lowercase()
        val aes128 = "aes128" in p && "aes256" !in p
        val gcm = "gcm" in p
        val sha = when {
            "sha512" in p || "sha2_512" in p -> 512
            "sha384" in p || "sha2_384" in p -> 384
            "sha1" in p && "sha256" !in p -> 1
            else -> 256
        }
        val dh = when {
            "ecp384" in p -> 20
            "ecp256" in p -> 19
            "modp1024" in p -> 2
            "modp2048" in p -> 14
            else -> 14
        }
        return Proposal(
            windowsCipher = if (aes128) "AES128" else "AES256",
            windowsEspCipher = when {
                gcm -> if (aes128) "GCMAES128" else "GCMAES256"
                aes128 -> "AES128"
                else -> "AES256"
            },
            windowsIntegrity = when (sha) { 512, 384 -> "SHA384"; 1 -> "SHA1"; else -> "SHA256" },
            windowsAuth = when {
                gcm -> if (aes128) "GCMAES128" else "GCMAES256"
                sha == 1 -> "SHA196"
                else -> "SHA256128"
            },
            windowsDh = when (dh) { 20 -> "ECP384"; 19 -> "ECP256"; 2 -> "Group2"; else -> "Group14" },
            appleCipher = when {
                gcm -> if (aes128) "AES-128-GCM" else "AES-256-GCM"
                aes128 -> "AES-128"
                else -> "AES-256"
            },
            appleIntegrity = when (sha) { 512 -> "SHA2-512"; 384 -> "SHA2-384"; 1 -> "SHA1-96"; else -> "SHA2-256" },
            appleDh = dh,
        )
    }

    private fun onPath(tool: String): Boolean =
        System.getenv("PATH").orEmpty().split(File.pathSeparator).any { File(it, tool).canExecute() }

    private fun execWithEnv(cmd: List<String>, env: Map<String, String>, timeoutSec: Long, input: String? = null): Pair<Int, String> = try {
        val p = ProcessBuilder(cmd).redirectErrorStream(true).also { it.environment().putAll(env) }.start()
        p.outputStream.use { stdin -> input?.let { stdin.write(it.toByteArray(Charsets.UTF_8)) } }
        val out = p.inputStream.bufferedReader().readText()
        if (!p.waitFor(timeoutSec, java.util.concurrent.TimeUnit.SECONDS)) {
            p.destroyForcibly()
            -1 to out
        } else {
            p.exitValue() to out
        }
    } catch (e: Exception) {
        -1 to (e.message ?: "exec failed")
    }

    private fun fail(message: String): Result<Unit> = Result.failure(IllegalStateException(message))

    companion object {
        const val NAME = "ZedSecure IKEv2"
        private const val PAYLOAD_ID = "dev.cluvex.zedsecure.ikev2"
        private val STRONGSWAN_PLUGIN = listOf(
            "/usr/lib/NetworkManager/VPN/nm-strongswan-service.name",
            "/usr/lib64/NetworkManager/VPN/nm-strongswan-service.name",
            "/etc/NetworkManager/VPN/nm-strongswan-service.name",
        )
    }
}
