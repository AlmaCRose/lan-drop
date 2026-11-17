using System.Diagnostics;
using System.Runtime.InteropServices;

namespace LanDrop.Core;

// Stops the computer from going to sleep while a transfer runs. Best effort on every system.
static class KeepAwake
{
    static readonly object gate = new();
    static int count;
    static IntPtr winRequest;
    static Process helper;

    public static void Begin()
    {
        lock (gate)
        {
            if (count++ > 0) return;
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    var ctx = new ReasonContext { Version = 0, Flags = 1, Reason = "LAN Drop is transferring files" };
                    winRequest = PowerCreateRequest(ref ctx);
                    if (winRequest != IntPtr.Zero && winRequest != new IntPtr(-1)) PowerSetRequest(winRequest, 1 /* system required */);
                }
                else if (OperatingSystem.IsMacOS())
                    helper = Start("caffeinate", "-i -w " + Environment.ProcessId);
                else if (OperatingSystem.IsLinux())
                    helper = Start("systemd-inhibit", "--what=sleep:idle --who=\"LAN Drop\" --why=\"Transferring files\" --mode=block sleep 2147483647");
            }
            catch { }
        }
    }

    public static void End()
    {
        lock (gate)
        {
            if (count == 0 || --count > 0) return;
            try
            {
                if (winRequest != IntPtr.Zero && winRequest != new IntPtr(-1))
                {
                    PowerClearRequest(winRequest, 1);
                    CloseHandle(winRequest);
                }
            }
            catch { }
            winRequest = IntPtr.Zero;
            try { if (helper != null && !helper.HasExited) helper.Kill(entireProcessTree: true); } catch { }
            helper = null;
        }
    }

    static Process Start(string file, string args) =>
        Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true });

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct ReasonContext
    {
        public uint Version;
        public uint Flags;
        [MarshalAs(UnmanagedType.LPWStr)] public string Reason;
    }

    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr PowerCreateRequest(ref ReasonContext context);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool PowerSetRequest(IntPtr handle, int type);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool PowerClearRequest(IntPtr handle, int type);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
}
