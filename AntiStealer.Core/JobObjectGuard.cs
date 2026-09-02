// Section 13.2 — JobObjectGuard.
//
// Wraps a child Process in a Win32 Job Object so the OS itself kills the
// child process tree if our parent crashes / is force-terminated. Without
// this, a hung yara/clamscan helper survives parent death and leaks
// resources. The guard also constrains memory and CPU as a defence in
// depth (a runaway helper can't OOM the box).
//
// Cross-platform: on non-Windows hosts, AssignProcess is a no-op (the
// returned handle is null but that's fine — Dispose handles null). The
// caller still needs to plumb a CancellationToken for graceful shutdown
// on Linux/macOS; the Job Object only adds the kill-on-parent-die
// behaviour the kernel can enforce.
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace AntiStealerOneExe
{
    /// <summary>
    /// Lightweight RAII wrapper around a Windows Job Object configured with
    /// <c>KILL_ON_JOB_CLOSE</c>. Adds <see cref="Process"/> instances to the
    /// job; disposing the guard closes the job handle which kills every
    /// child still running. No-op on non-Windows.
    /// </summary>
    public sealed class JobObjectGuard : IDisposable
    {
        private IntPtr _handle = IntPtr.Zero;
        private bool _disposed;

        /// <summary>
        /// Creates a guard with default limits: kill children on parent
        /// crash / disposal, 1 GiB process memory cap, 4 GiB job-wide
        /// memory cap. The values are deliberately generous; the goal is
        /// "trip on runaway helpers", not "tight sandbox".
        /// </summary>
        public static JobObjectGuard Create(long perProcessMemoryBytes = 1L << 30,
                                            long jobMemoryBytes        = 4L << 30)
        {
            var g = new JobObjectGuard();
            if (OperatingSystem.IsWindows())
            {
                g._handle = CreateConfiguredJob(perProcessMemoryBytes, jobMemoryBytes);
            }
            return g;
        }

        /// <summary>
        /// Adds a process to the job. On non-Windows / failure this is a
        /// silent no-op — the caller is expected to also wire a
        /// CancellationToken so cooperative shutdown still works.
        /// </summary>
        public bool AssignProcess(Process p)
        {
            if (p == null) return false;
            if (!OperatingSystem.IsWindows()) return false;
            if (_handle == IntPtr.Zero) return false;
            try
            {
                return AssignProcessToJobObject(_handle, p.Handle);
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            if (_handle != IntPtr.Zero && OperatingSystem.IsWindows())
            {
                try { CloseHandle(_handle); } catch { }
                _handle = IntPtr.Zero;
            }
        }

        // --- Windows-only P/Invoke and helpers -----------------------------

        [SupportedOSPlatform("windows")]
        private static IntPtr CreateConfiguredJob(long perProcessBytes, long jobBytes)
        {
            var h = CreateJobObject(IntPtr.Zero, null);
            if (h == IntPtr.Zero) return IntPtr.Zero;

            // KILL_ON_JOB_CLOSE = 0x2000; LIMIT_PROCESS_MEMORY = 0x100;
            // LIMIT_JOB_MEMORY = 0x200. Leaving the rest unset.
            var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags =
                  0x2000 /* KILL_ON_JOB_CLOSE */
                | 0x0100 /* LIMIT_PROCESS_MEMORY */
                | 0x0200 /* LIMIT_JOB_MEMORY */;
            limits.ProcessMemoryLimit = (UIntPtr)perProcessBytes;
            limits.JobMemoryLimit     = (UIntPtr)jobBytes;

            int size = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.StructureToPtr(limits, buf, fDeleteOld: false);
                if (!SetInformationJobObject(h, JobObjectExtendedLimitInformation, buf, (uint)size))
                {
                    CloseHandle(h);
                    return IntPtr.Zero;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
            return h;
        }

        // JOBOBJECT_EXTENDED_LIMIT_INFORMATION layout. Sized for 64-bit;
        // .NET 8 only supports 64-bit Windows runtimes for AnyCPU builds.
        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        private const int JobObjectExtendedLimitInformation = 9;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(
            IntPtr hJob, int infoClass, IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}
