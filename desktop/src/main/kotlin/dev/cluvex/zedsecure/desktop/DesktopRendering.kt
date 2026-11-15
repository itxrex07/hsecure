package dev.cluvex.zedsecure.desktop

import dev.cluvex.zedsecure.desktop.core.Os
import dev.cluvex.zedsecure.domain.model.RenderingMode
import dev.cluvex.zedsecure.ui.platform.AutomaticRendering

object DesktopRendering {
    enum class Source { External, Flag, Environment, Setting, Automatic }
    data class Decision(val software: Boolean, val source: Source, val automatic: AutomaticRendering)
    @Volatile var automatic: AutomaticRendering = AutomaticRendering.Gpu
        private set
    fun automaticFor(os: Os, env: Map<String, String>, nvidiaDriver: String?): AutomaticRendering =
        if (os == Os.WINDOWS) AutomaticRendering.SoftwareWindows else AutomaticRendering.Gpu
    fun decide(mode: RenderingMode, args: Array<String>, env: Map<String, String>, skikoProperty: String?, os: Os, nvidiaDriver: String?): Decision {
        val automatic = automaticFor(os, env, nvidiaDriver)
        val external = env["SKIKO_RENDER_API"]?.takeIf { it.isNotBlank() } ?: skikoProperty?.takeIf { it.isNotBlank() }
        if (external != null) return Decision(external.uppercase().startsWith("SOFTWARE"), Source.External, automatic)
        if ("--software-rendering" in args) return Decision(true, Source.Flag, automatic)
        if ("--gpu-rendering" in args) return Decision(false, Source.Flag, automatic)
        when (env["ZEDSECURE_RENDERING"]?.trim()?.lowercase()) {
            "software" -> return Decision(true, Source.Environment, automatic)
            "gpu" -> return Decision(false, Source.Environment, automatic)
        }
        when (env["ZEDSECURE_SOFTWARE_RENDERING"]?.trim()?.lowercase()) {
            "1", "true", "yes" -> return Decision(true, Source.Environment, automatic)
            "0", "false", "no" -> return Decision(false, Source.Environment, automatic)
        }
        return when (mode) {
            RenderingMode.Software -> Decision(true, Source.Setting, automatic)
            RenderingMode.Gpu -> Decision(false, Source.Setting, automatic)
            RenderingMode.Auto -> Decision(automatic != AutomaticRendering.Gpu, Source.Automatic, automatic)
        }
    }
    fun apply(mode: RenderingMode, args: Array<String>): Decision {
        val decision = decide(mode, args, System.getenv(), System.getProperty("skiko.renderApi"), Os.current, null)
        automatic = decision.automatic
        if (decision.software && decision.source != Source.External) System.setProperty("skiko.renderApi", "SOFTWARE")
        return decision
    }
}
