// End-to-end tests: two LAN Drop peers talk to each other over loopback in this process.
//   dotnet run --project tests/LanDrop.Tests                 run everything
//   dotnet run --project tests/LanDrop.Tests -- --verbose    also print every log line
//   dotnet run --project tests/LanDrop.Tests -- --interop <LanDrop 2 exe>   also test against the old Windows app
using System.Diagnostics;
using System.Security.Cryptography;
using LanDrop.Core;

static class Program
{
    static bool verbose;
    static int port = 51000 + Random.Shared.Next(0, 2000) * 4;
    static string work;
    static string src;
    static readonly TimeSpan Wait = TimeSpan.FromSeconds(60);

    static int Main(string[] args)
    {
        verbose = args.Contains("--verbose");
        int ix = Array.IndexOf(args, "--interop");
        string oldExe = ix >= 0 && ix + 1 < args.Length ? Path.GetFullPath(args[ix + 1]) : null;

        work = Path.Combine(Path.GetTempPath(), "landrop-tests-" + Guid.NewGuid().ToString("N")[..8]);
        src = Path.Combine(work, "src", "Test Folder");
        Console.WriteLine($"LAN Drop tests on {System.Runtime.InteropServices.RuntimeInformation.OSDescription}");
        Console.WriteLine($"Work folder: {work}");
        MakeData();

        var tests = new List<(string, Action)>
        {
            ("Invite keys encode and decode", InviteRoundTrip),
            ("Incoming paths can't escape the chosen folder", SafePaths),
            ("Same network: address and code", SameNetworkCode),
            ("Invite key, then sending again skips everything", InviteKeyAndResend),
            ("Both sides can send on one connection", BothDirections),
            ("The code is refused from outside the network", CodeRefusedFromOutside),
            ("A changed secret is refused", WrongSecret),
            ("A changed certificate is refused", WrongCertificate),
            ("Five wrong codes change the code", WrongCodes),
            ("Declining", Declining),
            ("Sender cancels", SenderCancels),
            ("Receiver cancels", ReceiverCancels),
            ("Connection lost mid-copy, then resume", LostThenResume),
        };
        if (oldExe != null)
        {
            tests.Add(("LAN Drop 2 waits, this version sends with the key", () => InteropOldHosts(oldExe, useKey: true)));
            tests.Add(("LAN Drop 2 waits, this version sends with the code", () => InteropOldHosts(oldExe, useKey: false)));
            tests.Add(("This version waits, LAN Drop 2 sends with the key", () => InteropNewHosts(oldExe)));
        }

        int failed = 0;
        foreach (var (name, run) in tests)
        {
            var sw = Stopwatch.StartNew();
            try
            {
                run();
                Console.WriteLine($"PASS  {name}  ({sw.Elapsed.TotalSeconds:0.0}s)");
            }
            catch (Exception ex)
            {
                failed++;
                Console.WriteLine($"FAIL  {name}  ({sw.Elapsed.TotalSeconds:0.0}s)\n      {ex.Message}");
            }
        }
        Console.WriteLine(failed == 0 ? $"\nAll {tests.Count} tests passed." : $"\n{failed} of {tests.Count} tests failed.");
        try { Directory.Delete(work, true); } catch { }
        return failed == 0 ? 0 : 1;
    }

    // ---------- test data ----------

    static void MakeData()
    {
        var rng = new Random(42);
        Directory.CreateDirectory(Path.Combine(src, "sub", "deeper"));
        string uni = Path.Combine(src, "Ünï 文件夹");
        Directory.CreateDirectory(uni);
        var buf = new byte[4 << 20];
        using (var fs = File.Create(Path.Combine(src, "big.bin")))
            for (int i = 0; i < 32; i++) { rng.NextBytes(buf); fs.Write(buf); } // 128 MB
        for (int i = 0; i < 60; i++)
        {
            var b = new byte[rng.Next(0, 200000)];
            rng.NextBytes(b);
            File.WriteAllBytes(Path.Combine(src, "sub", "deeper", $"small_{i}.dat"), b);
        }
        File.WriteAllBytes(Path.Combine(src, "empty.txt"), Array.Empty<byte>());
        File.WriteAllText(Path.Combine(uni, "こんにちは.txt"), "hello");
        var mb = new byte[1 << 20]; rng.NextBytes(mb);
        File.WriteAllBytes(Path.Combine(src, "exactly1MB.bin"), mb);
        var mb1 = new byte[(1 << 20) + 1]; rng.NextBytes(mb1);
        File.WriteAllBytes(Path.Combine(src, "1MBplus1.bin"), mb1);
        // A file with an old date, to check dates come across.
        File.SetLastWriteTimeUtc(Path.Combine(src, "exactly1MB.bin"), new DateTime(2020, 5, 17, 12, 0, 0, DateTimeKind.Utc));
    }

    static string NewDest(string name)
    {
        string d = Path.Combine(work, "dst-" + name);
        if (Directory.Exists(d)) Directory.Delete(d, true);
        Directory.CreateDirectory(d);
        return d;
    }

    static Dictionary<string, (string Hash, DateTime Modified)> Tree(string root)
    {
        var map = new Dictionary<string, (string, DateTime)>();
        if (!Directory.Exists(root)) return map;
        foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            string rel = Path.GetRelativePath(root, f).Replace('\\', '/').Normalize();
            using var s = File.OpenRead(f);
            map[rel] = (Convert.ToHexString(SHA256.HashData(s)), File.GetLastWriteTimeUtc(f));
        }
        return map;
    }

    static void SameTree(string dest, params string[] extraAllowed)
    {
        var a = Tree(src);
        var b = Tree(Path.Combine(dest, "Test Folder"));
        foreach (var x in extraAllowed) b.Remove(x);
        Check(a.Count == b.Count, $"expected {a.Count} files, found {b.Count}");
        foreach (var (rel, (hash, mod)) in a)
        {
            Check(b.TryGetValue(rel, out var got), "missing " + rel);
            Check(got.Hash == hash, "contents differ: " + rel);
            Check(Math.Abs((got.Modified - mod).TotalSeconds) < 2.1, $"date differs: {rel} ({got.Modified:u} vs {mod:u})");
        }
        NoPartFiles(dest);
    }

    static void NoPartFiles(string dest) =>
        Check(!Directory.EnumerateFiles(dest, "*.landrop-part", SearchOption.AllDirectories).Any(), "a .landrop-part file was left behind");

    static void Check(bool ok, string message)
    {
        if (!ok) throw new Exception(message);
    }

    static void WaitFor(Func<bool> cond, string what, TimeSpan? timeout = null)
    {
        var sw = Stopwatch.StartNew();
        while (!cond())
        {
            if (sw.Elapsed > (timeout ?? Wait)) throw new Exception("timed out waiting for " + what);
            Thread.Sleep(10);
        }
    }

    // ---------- peers ----------

    sealed class Side : IPeerHost, IDisposable
    {
        public readonly string Name;
        public readonly Peer Peer;
        public readonly List<string> Logs = new();
        public Func<Offer, AcceptChoice> Chooser = _ => null;
        public Action<Side> OnStarted;
        public volatile string Invite, ConnectError;
        public readonly List<string> Codes = new();
        public readonly List<TransferResult> Results = new();

        public Side(string name, PeerOptions o)
        {
            Name = name;
            o.MachineName = name;
            Peer = new Peer(this, o);
        }

        public void Log(string m)
        {
            lock (Logs) Logs.Add(m);
            if (verbose) Console.WriteLine($"      [{Name}] {m}");
        }
        public void StateChanged() { }
        public void CodeChanged(string code) { lock (Codes) Codes.Add(code); }
        public void InviteReady(string key, string pub) => Invite = key;
        public void ConnectFailed(string message) => ConnectError = message;
        public AcceptChoice ChooseIncoming(string peerName, Offer offer) => Chooser(offer);
        public void TransferStarted(string verb, long total, int count) => OnStarted?.Invoke(this);
        public void TransferEnded(TransferResult r) { lock (Results) Results.Add(r); }
        public int ResultCount { get { lock (Results) return Results.Count; } }
        public TransferResult Last { get { lock (Results) return Results[^1]; } }
        public void Dispose() => Peer.Dispose();
    }

    static (Side waiter, Side caller) Pair(bool viaKey, PeerOptions waiterOptions = null)
    {
        int p = port += 4;
        var o = waiterOptions ?? new PeerOptions();
        o.Port = p;
        o.Loopback = true;
        var a = new Side("WAITER", o);
        var b = new Side("CALLER", new PeerOptions { Port = p, Loopback = true });
        Check(a.Peer.StartHosting("123456") == null, "couldn't start waiting");
        WaitFor(() => a.Invite != null, "the invite key");
        string err = viaKey ? b.Peer.Connect(a.Invite, null) : b.Peer.Connect("127.0.0.1", "123456");
        Check(err == null, "connect refused: " + err);
        WaitFor(() => (a.Peer.IsConnected && b.Peer.IsConnected) || b.ConnectError != null, "the connection");
        Check(b.ConnectError == null, "connect failed: " + b.ConnectError);
        return (a, b);
    }

    static void Send(Side from, Side to, string dest, bool skipExisting = true)
    {
        int f0 = from.ResultCount, t0 = to.ResultCount;
        to.Chooser = _ => new AcceptChoice { Folder = dest, SkipExisting = skipExisting };
        Check(from.Peer.Offer(new[] { src }) == null, "offer refused");
        WaitFor(() => from.ResultCount > f0 && to.ResultCount > t0, "the transfer to finish");
    }

    // ---------- tests ----------

    static void InviteRoundTrip()
    {
        var inv = new Invite { Port = 50505, Fingerprint = Util.RandomBytes(32), Secret = Util.RandomBytes(16) };
        inv.Addresses.Add(System.Net.IPAddress.Parse("203.0.113.9"));
        inv.Addresses.Add(System.Net.IPAddress.Parse("192.168.1.20"));
        string key = inv.Encode();
        var back = Invite.TryParse("  " + key[..20] + "\n" + key[20..] + " ");
        Check(back != null, "key didn't parse");
        Check(back.Port == 50505 && back.Addresses.Count == 2 && back.Addresses[0].ToString() == "203.0.113.9", "addresses or port changed");
        Check(Util.SameBytes(back.Fingerprint, inv.Fingerprint) && Util.SameBytes(back.Secret, inv.Secret), "fingerprint or secret changed");
        Check(Invite.TryParse(key[..^4]) == null, "a cut-off key was accepted");
        Check(Invite.TryParse("LD1-garbage!!") == null, "a damaged key was accepted");
        Check(Invite.TryParse("192.168.1.5") == null, "an address was read as a key");
    }

    static void SafePaths()
    {
        void Throws(string p)
        {
            try { Util.SafeRelPath(p); }
            catch (InvalidDataException) { return; }
            throw new Exception("accepted unsafe path " + p);
        }
        Throws("../evil.txt");
        Throws("a/../../evil.txt");
        Throws("a\\..\\evil.txt");
        Throws("");
        char s = Path.DirectorySeparatorChar;
        Check(Util.SafeRelPath("/etc/passwd") == $"etc{s}passwd", "a rooted path wasn't made relative");
        Check(Util.SafeRelPath("C:/Windows/x") == $"C_{s}Windows{s}x", "a drive letter wasn't neutralised");
        Check(Util.SafeRelPath("a/CON.txt") == $"a{s}_CON.txt", "a reserved Windows name wasn't renamed");
        Check(Util.SafeRelPath("a/b?.txt") == $"a{s}b_.txt", "an invalid character wasn't replaced");
        Check(Util.SafeRelPath("trailing. ") == "trailing", "trailing dots and spaces weren't removed");
    }

    static void SameNetworkCode()
    {
        string dest = NewDest("code");
        // A different file already has one of the names: it must be kept, and the new one saved beside it.
        Directory.CreateDirectory(Path.Combine(dest, "Test Folder"));
        File.WriteAllText(Path.Combine(dest, "Test Folder", "empty.txt"), "older, different file");
        var (a, b) = Pair(viaKey: false);
        using (a) using (b)
        {
            Send(b, a, dest);
            Check(a.Last.Complete && b.Last.Complete, "not complete: " + a.Last.Summary + " / " + b.Last.Summary);
            Check(File.ReadAllText(Path.Combine(dest, "Test Folder", "empty.txt")) == "older, different file", "an existing file was overwritten");
            File.Move(Path.Combine(dest, "Test Folder", "empty (2).txt"), Path.Combine(work, "renamed-empty.txt"));
            File.Delete(Path.Combine(dest, "Test Folder", "empty.txt"));
            File.Move(Path.Combine(work, "renamed-empty.txt"), Path.Combine(dest, "Test Folder", "empty.txt"));
            File.SetLastWriteTimeUtc(Path.Combine(dest, "Test Folder", "empty.txt"), File.GetLastWriteTimeUtc(Path.Combine(src, "empty.txt")));
            SameTree(dest);
        }
    }

    static void InviteKeyAndResend()
    {
        string dest = NewDest("key");
        var (a, b) = Pair(viaKey: true);
        using (a) using (b)
        {
            Send(b, a, dest);
            Check(a.Last.Complete && b.Last.Complete, "not complete: " + a.Last.Summary);
            SameTree(dest);
            Send(b, a, dest);
            Check(a.Last.Ok == 0 && a.Last.Skipped == Tree(src).Count, $"second send wasn't all skipped: {a.Last.Summary}");
        }
    }

    static void BothDirections()
    {
        string d1 = NewDest("dir1"), d2 = NewDest("dir2");
        var (a, b) = Pair(viaKey: true);
        using (a) using (b)
        {
            Send(b, a, d1);
            Send(a, b, d2);
            Check(a.Last.Complete && b.Last.Complete, "not complete");
            SameTree(d1);
            SameTree(d2);
        }
    }

    static void CodeRefusedFromOutside()
    {
        int p = port += 4;
        using var a = new Side("WAITER", new PeerOptions { Port = p, Loopback = true, PublicOnly = true });
        using var b = new Side("CALLER", new PeerOptions { Port = p, Loopback = true });
        a.Peer.StartHosting("123456");
        WaitFor(() => a.Invite != null, "the invite key");
        b.Peer.Connect("127.0.0.1", "123456");
        WaitFor(() => b.ConnectError != null, "the refusal");
        Check(b.ConnectError.Contains("invite key"), "unexpected message: " + b.ConnectError);
        Check(a.Peer.IsHosting, "the waiting side stopped waiting");
        b.ConnectError = null;
        b.Peer.Connect(a.Invite, null);
        WaitFor(() => b.Peer.IsConnected || b.ConnectError != null, "the key connection");
        Check(b.Peer.IsConnected, "the key was refused: " + b.ConnectError);
    }

    static string Tamper(string key, int fromEnd)
    {
        int i = key.Length - fromEnd;
        char c = key[i] == 'A' ? 'B' : 'A';
        return key[..i] + c + key[(i + 1)..];
    }

    static void WrongSecret() => RefusedKey(k => Tamper(k, 3), "doesn't match");
    static void WrongCertificate() => RefusedKey(k => Tamper(k, 30), "isn't the one");

    static void RefusedKey(Func<string, string> change, string expect)
    {
        int p = port += 4;
        using var a = new Side("WAITER", new PeerOptions { Port = p, Loopback = true });
        using var b = new Side("CALLER", new PeerOptions { Port = p, Loopback = true });
        a.Peer.StartHosting();
        WaitFor(() => a.Invite != null, "the invite key");
        b.Peer.Connect(change(a.Invite), null);
        WaitFor(() => b.ConnectError != null || b.Peer.IsConnected, "the refusal");
        Check(!b.Peer.IsConnected, "a changed key got in");
        Check(b.ConnectError.Contains(expect), "unexpected message: " + b.ConnectError);
    }

    static void WrongCodes()
    {
        int p = port += 4;
        using var a = new Side("WAITER", new PeerOptions { Port = p, Loopback = true });
        a.Peer.StartHosting("111111");
        for (int i = 0; i < 5; i++)
        {
            using var b = new Side("CALLER", new PeerOptions { Port = p, Loopback = true });
            b.Peer.Connect("127.0.0.1", "999999");
            WaitFor(() => b.ConnectError != null, "the refusal");
            Check(b.ConnectError.Contains("code is wrong"), "unexpected message: " + b.ConnectError);
        }
        WaitFor(() => a.Peer.PairCode != "111111", "the code to change", TimeSpan.FromSeconds(5));
        Check(a.Peer.IsHosting, "stopped waiting");
    }

    static void Declining()
    {
        string dest = NewDest("decline");
        var (a, b) = Pair(viaKey: true);
        using (a) using (b)
        {
            a.Chooser = _ => null;
            Check(b.Peer.Offer(new[] { src }) == null, "offer refused");
            WaitFor(() => b.ResultCount > 0, "the decline");
            Check(b.Last.Declined, "not reported as declined: " + b.Last.Summary);
            Check(!Directory.EnumerateFileSystemEntries(dest).Any(), "files were saved after declining");
            WaitFor(() => !a.Peer.IsBusy && !b.Peer.IsBusy, "both sides to be free");
        }
    }

    static void SenderCancels()
    {
        string dest = NewDest("sendcancel");
        var (a, b) = Pair(viaKey: true);
        using (a) using (b)
        {
            b.OnStarted = s => s.Peer.Cancel();
            Send(b, a, dest);
            Check(a.Last.Cancelled && b.Last.Cancelled, "not reported as cancelled");
            NoPartFiles(dest);
            Check(b.Peer.IsConnected, "cancelling dropped the connection");
        }
    }

    static void ReceiverCancels()
    {
        string dest = NewDest("recvcancel");
        var (a, b) = Pair(viaKey: true);
        using (a) using (b)
        {
            a.OnStarted = s => s.Peer.Cancel();
            Send(b, a, dest);
            Check(a.Last.Cancelled && b.Last.Cancelled, "not reported as cancelled");
            NoPartFiles(dest);
            Check(!Directory.EnumerateFiles(dest, "*", SearchOption.AllDirectories).Any(), "files were saved after cancelling");
        }
    }

    static void LostThenResume()
    {
        string dest = NewDest("lost");
        var (a, b) = Pair(viaKey: false);
        using (a)
        using (b)
        {
            // Drop the connection once 16 MB of the 128 MB file have gone across.
            b.OnStarted = s => new Thread(() =>
            {
                while (s.Peer.DoneBytes < (16 << 20) && s.Peer.IsTransferring) Thread.SpinWait(100);
                s.Peer.Disconnect();
            }) { IsBackground = true }.Start();
            Send(b, a, dest);
            Check(a.Last.ConnectionLost, "the receiver didn't report a lost connection: " + a.Last.Summary);
            WaitFor(() => !a.Peer.IsConnected && !a.Peer.IsBusy, "the receiver to settle");
            NoPartFiles(dest);
        }
        var (a2, b2) = Pair(viaKey: true);
        using (a2) using (b2)
        {
            Send(b2, a2, dest);
            Check(a2.Last.Complete, "the resumed copy didn't finish: " + a2.Last.Summary);
            SameTree(dest);
        }
    }

    // ---------- against LAN Drop 2 for Windows ----------

    static Process StartOld(string exe, string args) =>
        Process.Start(new ProcessStartInfo(exe, args) { UseShellExecute = false });

    static void InteropOldHosts(string exe, bool useKey)
    {
        string dest = NewDest("old-hosts-" + useKey);
        int p = port += 4;
        string inviteFile = Path.Combine(work, $"invite-{p}.txt");
        using var old = StartOld(exe, $"--test-port {p} --test-loopback --test-host 123456 --test-accept \"{dest}\" --test-exit --test-invite-file \"{inviteFile}\"");
        try
        {
            WaitFor(() => File.Exists(inviteFile) && new FileInfo(inviteFile).Length > 0, "LAN Drop 2's invite key");
            using var b = new Side("NEW", new PeerOptions { Port = p, Loopback = true });
            string err = useKey ? b.Peer.Connect(File.ReadAllText(inviteFile).Trim(), null) : b.Peer.Connect("127.0.0.1", "123456");
            Check(err == null, err);
            WaitFor(() => b.Peer.IsConnected || b.ConnectError != null, "the connection");
            Check(b.Peer.IsConnected, "couldn't connect: " + b.ConnectError);
            Check(b.Peer.Offer(new[] { src }) == null, "offer refused");
            WaitFor(() => b.ResultCount > 0, "the transfer");
            Check(b.Last.Complete, "not complete: " + b.Last.Summary);
            Check(old.WaitForExit(30000) && old.ExitCode == 0, "LAN Drop 2 reported a problem");
            SameTree(dest);
        }
        finally { if (!old.HasExited) old.Kill(); }
    }

    static void InteropNewHosts(string exe)
    {
        string dest = NewDest("new-hosts");
        int p = port += 4;
        using var a = new Side("NEW", new PeerOptions { Port = p, Loopback = true });
        a.Chooser = _ => new AcceptChoice { Folder = dest };
        a.Peer.StartHosting();
        WaitFor(() => a.Invite != null, "the invite key");
        using var old = StartOld(exe, $"--test-port {p} --test-connect {a.Invite} x --test-send \"{src}\" --test-exit");
        try
        {
            WaitFor(() => a.ResultCount > 0, "the transfer");
            Check(a.Last.Complete, "not complete: " + a.Last.Summary);
            Check(old.WaitForExit(30000) && old.ExitCode == 0, "LAN Drop 2 reported a problem");
            SameTree(dest);
        }
        finally { if (!old.HasExited) old.Kill(); }
    }
}
