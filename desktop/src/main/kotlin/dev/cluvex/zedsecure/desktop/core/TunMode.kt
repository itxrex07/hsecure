package dev.cluvex.zedsecure.desktop.core

import java.io.File

class TunMode(private val socksPort: Int, private val workDir: File, private val bypassIps: List<String> = emptyList(), private val udpOverTcp: Boolean = false, private val dnsServers: String = ZeptunTun.DEFAULT_DNS, private val askPassword: ((retry: Boolean) -> AdminAnswer?)? = null, private val excludeCgroup: String? = null) : DesktopTun {
    override fun start(): Boolean = false
    override fun stop() = Unit
    companion object {
        fun supported(os: Os = Os.current): Boolean = os == Os.WINDOWS
        fun usesZeptun(os: Os = Os.current, zeptunOnWindows: Boolean = false): Boolean = os == Os.WINDOWS && zeptunOnWindows
    }
    object Factory {
        fun create(workDir: File, socksPort: Int, bypassIps: List<String>, udpOverTcp: Boolean, dnsServers: String, askPassword: ((retry: Boolean) -> AdminAnswer?)?, allowApps: List<File> = emptyList(), zeptunOnWindows: Boolean = false, excludeCgroup: String? = null, hevOnMac: Boolean = false): DesktopTun? = when {
            Os.current != Os.WINDOWS -> null
            zeptunOnWindows -> ZeptunBinary.extract(workDir)?.let { ZeptunTun(it, socksPort, workDir, bypassIps, udpOverTcp, dnsServers, allowApps = allowApps) }
            else -> HevBinary.extract(workDir)?.let { HevWindowsTun(it, socksPort, workDir, bypassIps, udpOverTcp, dnsServers) }
        }
    }
}
