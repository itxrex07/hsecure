package dev.cluvex.zedsecure.desktop.platform

import dev.cluvex.zedsecure.ui.platform.LiveStats

object DesktopMonitor {
    private var lastCpuNanos: Map<Long, Long> = emptyMap()
    private var lastSampleAt: Long = 0L
    fun sample(): LiveStats {
        val self = ProcessHandle.current()
        val processes = listOf(self) + runCatching { self.descendants().toList() }.getOrDefault(emptyList())
        return LiveStats(cpuPercent = cpuPercent(processes), coreCount = Runtime.getRuntime().availableProcessors().coerceAtLeast(1), threads = Thread.activeCount(), processUptimeMs = self.info().startInstant().map { System.currentTimeMillis() - it.toEpochMilli() }.orElse(null))
    }
    private fun cpuPercent(processes: List<ProcessHandle>): Float? {
        val now = System.nanoTime(); val current = HashMap<Long, Long>(); var spent = 0L
        for (process in processes) {
            val nanos = process.info().totalCpuDuration().map { it.toNanos() }.orElse(null) ?: continue
            current[process.pid()] = nanos
            lastCpuNanos[process.pid()]?.let { spent += (nanos - it).coerceAtLeast(0L) }
        }
        val elapsed = now - lastSampleAt; lastCpuNanos = current; lastSampleAt = now
        return if (elapsed <= 0L || current.isEmpty()) null else (spent.toFloat() / elapsed * 100f).coerceAtLeast(0f)
    }
    fun cryptoAcceleration(): String = ""
}
