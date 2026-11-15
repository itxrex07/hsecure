package dev.cluvex.zedsecure.desktop.core

object SystemProxy {
    fun set(host: String, port: Int): Boolean = Os.current == Os.WINDOWS && windows(host, port, on = true)
    fun clear(): Boolean = Os.current == Os.WINDOWS && windows("", 0, on = false)
    private fun windows(host: String, port: Int, on: Boolean): Boolean {
        val key = """HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"""
        return if (on) {
            exec("reg", "add", key, "/v", "ProxyServer", "/t", "REG_SZ", "/d", "$host:$port", "/f").first == 0 &&
                exec("reg", "add", key, "/v", "ProxyOverride", "/t", "REG_SZ", "/d",
                    "localhost;127.*;10.*;172.16.*;192.168.*;<local>", "/f").first == 0 &&
                exec("reg", "add", key, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f").first == 0
        } else {
            exec("reg", "add", key, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f").first == 0
        }
    }

}
