package dev.cluvex.zedsecure.desktop.core

import java.io.File

object EngineCgroup {
    fun start(builder: ProcessBuilder, relative: String?): Process = builder.start()
    fun remove(relative: String) = Unit
}
