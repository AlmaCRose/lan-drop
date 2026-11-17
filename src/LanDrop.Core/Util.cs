using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LanDrop.Core;

public static class Util
{
    public static string Bytes(long b)
    {
        if (b < 1024) return b + " B";
        double v = b;
        string[] units = { "KB", "MB", "GB", "TB" };
        int i = -1;
        do { v /= 1024; i++; } while (v >= 1024 && i < units.Length - 1);
        return v.ToString(v >= 100 ? "0" : "0.0") + " " + units[i];
    }

    public static string Count(int n, string one, string many) => n.ToString("N0") + " " + (n == 1 ? one : many);

    public static string Duration(double s)
    {
        if (s < 60) return Math.Max(1, (int)s) + " sec";
        if (s < 3600) return (int)(s / 60) + " min";
        return (int)(s / 3600) + " hr " + (int)(s % 3600 / 60) + " min";
    }

    // Windows' rules are the strictest, so names that pass them work on every system.
    static readonly char[] Invalid = { '"', '<', '>', '|', ':', '*', '?', '\\', '/' };
    static readonly string[] Reserved = { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
        "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };

    // Turns a path sent by the other PC into a safe relative path that can't leave the chosen folder.
    public static string SafeRelPath(string rel)
    {
        var parts = new List<string>();
        foreach (var raw in rel.Split('/', '\\'))
        {
            string p = raw.Trim();
            if (p == "" || p == ".") continue;
            if (p == "..") throw new InvalidDataException("unsafe path");
            var sb = new StringBuilder();
            foreach (char ch in p) sb.Append(ch < 32 || Array.IndexOf(Invalid, ch) >= 0 ? '_' : ch);
            string s = sb.ToString().TrimEnd('.', ' ');
            if (s == "") s = "_";
            if (Reserved.Contains(s.Split('.')[0].ToUpperInvariant())) s = "_" + s;
            parts.Add(s);
        }
        if (parts.Count == 0) throw new InvalidDataException("empty path");
        return string.Join(Path.DirectorySeparatorChar, parts);
    }

    public static string UniqueName(string path)
    {
        string dir = Path.GetDirectoryName(path);
        string stem = Path.GetFileNameWithoutExtension(path);
        string ext = Path.GetExtension(path);
        for (int n = 2; ; n++)
        {
            string p = Path.Combine(dir, stem + " (" + n + ")" + ext);
            if (!File.Exists(p) && !Directory.Exists(p)) return p;
        }
    }

    public static bool IsDiskFull(Exception ex)
    {
        if (OperatingSystem.IsWindows())
        {
            int code = ex.HResult & 0xFFFF;
            return code == 0x70 || code == 0x27;
        }
        return ex.HResult == 28 /* ENOSPC */ || (ex.Message ?? "").Contains("No space left", StringComparison.OrdinalIgnoreCase);
    }

    public static void ReadFully(BinaryReader r, byte[] buf, int len)
    {
        int off = 0;
        while (off < len)
        {
            int n = r.Read(buf, off, len - off);
            if (n <= 0) throw new EndOfStreamException();
            off += n;
        }
    }

    // This PC's IPv4 addresses on its networks, home-network ones first.
    public static List<string> LocalAddresses()
    {
        var list = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    string s = ua.Address.ToString();
                    if (s.StartsWith("169.254.") || s.StartsWith("127.")) continue;
                    if (!list.Contains(s)) list.Add(s);
                }
            }
        }
        catch { }
        return list.OrderBy(a => a.StartsWith("192.168.") ? 0 : a.StartsWith("10.") ? 1 : a.StartsWith("100.") ? 3 : 2).ToList();
    }

    public static void AddPath(string path, List<OfferItem> items, List<string> problems)
    {
        string root = Path.GetPathRoot(path);
        if (path.Length > (root?.Length ?? 0)) path = path.TrimEnd('\\', '/');
        try
        {
            if (File.Exists(path))
            {
                var fi = new FileInfo(path);
                items.Add(new OfferItem { FullPath = fi.FullName, RelPath = CleanName(fi.Name), Size = fi.Length, Modified = fi.LastWriteTimeUtc });
            }
            else if (Directory.Exists(path))
            {
                var di = new DirectoryInfo(path);
                string name = di.Parent == null
                    ? (OperatingSystem.IsWindows() ? "Drive " + di.Name.TrimEnd('\\', ':') : "Root")
                    : CleanName(di.Name);
                Walk(di, name, items, problems);
            }
            else problems.Add(path + ": not found");
        }
        catch (Exception ex) { problems.Add(path + ": " + ex.Message); }
    }

    // On Mac and Linux a backslash is allowed in names; it would read as a folder break elsewhere.
    static string CleanName(string name) => OperatingSystem.IsWindows() ? name : name.Replace('\\', '_');

    static void Walk(DirectoryInfo dir, string rel, List<OfferItem> items, List<string> problems)
    {
        FileSystemInfo[] entries;
        try { entries = dir.GetFileSystemInfos(); }
        catch (Exception ex) { problems.Add(rel + ": " + ex.Message); return; }
        foreach (var e in entries.OrderBy(x => x.Name, StringComparer.Ordinal))
        {
            string r = rel + "/" + CleanName(e.Name);
            if (e.LinkTarget != null || (e.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                problems.Add(r + ": a shortcut/link, left out");
                continue;
            }
            if (e is DirectoryInfo sub) Walk(sub, r, items, problems);
            else if (e is FileInfo f)
            {
                if (f.Name == ".DS_Store") continue; // Mac folder-view settings, not wanted elsewhere
                items.Add(new OfferItem { FullPath = f.FullName, RelPath = r, Size = f.Length, Modified = f.LastWriteTimeUtc });
            }
        }
    }

    // Two dropped items with the same name would land on the same path; rename the later ones.
    public static void Dedupe(List<OfferItem> items)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var it in items)
        {
            if (seen.Add(it.RelPath)) continue;
            int slash = it.RelPath.LastIndexOf('/');
            string dir = slash >= 0 ? it.RelPath.Substring(0, slash + 1) : "";
            string name = it.RelPath.Substring(slash + 1);
            string stem = Path.GetFileNameWithoutExtension(name), ext = Path.GetExtension(name);
            for (int n = 2; ; n++)
            {
                string candidate = dir + stem + " (" + n + ")" + ext;
                if (seen.Add(candidate)) { it.RelPath = candidate; break; }
            }
        }
    }

    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);

    public static byte[] RandomBytes(int n) => RandomNumberGenerator.GetBytes(n);

    public static bool SameBytes(byte[] a, byte[] b) =>
        a != null && b != null && a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);

    // A throwaway certificate for this session's TLS. Nobody trusts it by name;
    // the invite key carries its fingerprint instead.
    public static X509Certificate2 MakeCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=LAN Drop", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var tmp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        // Windows and Mac TLS can't use an in-memory key directly; a round trip through PFX fixes that.
        return X509CertificateLoader.LoadPkcs12(tmp.Export(X509ContentType.Pfx, "landrop"), "landrop");
    }

    // Addresses on this side of a home router (or a Tailscale-style VPN).
    public static bool IsLocal(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily != AddressFamily.InterNetwork) return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal;
        var b = ip.GetAddressBytes();
        return b[0] == 10
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254)
            || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
    }

    static readonly HttpClient http = new() { Timeout = TimeSpan.FromSeconds(6), DefaultRequestHeaders = { { "User-Agent", "LAN Drop" } } };

    // This network's address on the internet, as seen from outside. Null if it can't be found.
    public static string PublicAddress()
    {
        foreach (var url in new[] { "https://api.ipify.org", "https://icanhazip.com" })
        {
            try
            {
                string s = http.GetStringAsync(url).GetAwaiter().GetResult().Trim();
                if (IPAddress.TryParse(s, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork && !IsLocal(ip)) return s;
            }
            catch { }
        }
        return null;
    }

    // Tries every address at once and keeps the first that answers.
    public static TcpClient ConnectAny(IList<IPAddress> addrs, int port, int timeoutMs)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        var attempts = addrs.Select(a =>
        {
            var c = new TcpClient(AddressFamily.InterNetwork);
            return (client: c, task: c.ConnectAsync(a, port, cts.Token).AsTask());
        }).ToList();
        var pending = attempts.ToList();
        TcpClient winner = null;
        while (winner == null && pending.Count > 0)
        {
            var done = Task.WhenAny(pending.Select(p => p.task)).GetAwaiter().GetResult();
            var hit = pending.First(p => p.task == done);
            pending.Remove(hit);
            if (done.Status == TaskStatus.RanToCompletion) winner = hit.client;
        }
        cts.Cancel();
        foreach (var a in attempts) if (a.client != winner) try { a.client.Dispose(); } catch { }
        return winner;
    }

    // Free space on the disk that holds this folder. Null if unknown.
    public static (string Disk, long Free)? FreeSpace(string folder)
    {
        try
        {
            string full = Path.GetFullPath(folder);
            DriveInfo best = null;
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (!d.IsReady) continue;
                    string root = d.RootDirectory.FullName;
                    bool match = OperatingSystem.IsWindows()
                        ? full.StartsWith(root, StringComparison.OrdinalIgnoreCase)
                        : root == "/" || full == root.TrimEnd('/') || full.StartsWith(root.TrimEnd('/') + "/", StringComparison.Ordinal);
                    if (match && (best == null || root.Length > best.RootDirectory.FullName.Length)) best = d;
                }
                catch { }
            }
            if (best == null) return null;
            string name = OperatingSystem.IsWindows() ? "drive " + best.Name.TrimEnd('\\') : best.RootDirectory.FullName;
            return (name, best.AvailableFreeSpace);
        }
        catch { return null; }
    }

    public static string DefaultSaveFolder() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
}
