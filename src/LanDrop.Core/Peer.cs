using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LanDrop.Core;

// One side of a LAN Drop connection: waits for or makes a connection, then sends and receives files.
// It has no window code; the app (or a test) talks to it through IPeerHost.
public sealed class Peer : IDisposable
{
    public const int DefaultPort = 50505;
    public enum Activity { None, Listing, Offering, Sending, Choosing, Receiving }

    const int ChunkSize = 1 << 20;
    const string Magic = "LANDROP2";
    const byte AuthCode = 1, AuthKey = 2;

    readonly IPeerHost host;
    readonly PeerOptions opt;
    readonly object gate = new();

    // Connection
    volatile TcpListener listener;
    volatile Connection conn;
    volatile bool connecting, userDisconnect, disposed;
    volatile string pairCode, inviteKey, publicAddress, offerSummary;

    // Transfer, shared
    int busyFlag, transferFlag;
    volatile Activity activity;
    long doneBytes;
    int fileNumber;
    volatile string currentFile = "";

    // Sending
    int offerCounter;
    volatile Offer outgoing;
    volatile bool sendCancel;

    // Receiving (touched only by the reader thread, except rxCancelled)
    Offer rxOffer;
    string rxRoot;
    volatile bool rxCancelled;
    int rxIndex = -1, rxOk, rxSkipped;
    List<string> rxFailed = new();
    FileStream rxStream;
    IncrementalHash rxHash;
    string rxPart, rxDest;
    long rxWritten;
    bool rxFileFailed;
    readonly byte[] recvBuf = new byte[ChunkSize];

    public Peer(IPeerHost host, PeerOptions options = null)
    {
        this.host = host;
        opt = options ?? new PeerOptions();
    }

    public bool IsConnected => conn != null;
    public bool IsHosting => listener != null;
    public bool IsConnecting => connecting;
    public bool IsBusy => Volatile.Read(ref busyFlag) != 0;
    public bool IsTransferring => Volatile.Read(ref transferFlag) != 0;
    public Activity CurrentActivity => activity;
    public string PeerName => conn?.PeerName;
    public string PeerAddress => conn?.PeerAddress;
    public string MachineName => opt.MachineName;
    public int Port => opt.Port;
    public string PairCode => pairCode;
    public string InviteKey => inviteKey;
    public string PublicAddress => publicAddress;
    public string OfferSummary => offerSummary;
    public long DoneBytes => Interlocked.Read(ref doneBytes);
    public long TotalBytes { get; private set; }
    public int FileNumber => Volatile.Read(ref fileNumber);
    public int FileCount { get; private set; }
    public string CurrentFile => currentFile;

    // ---------- helpers ----------

    void Log(string s) { try { host.Log(s); } catch { } }
    void Changed() { try { host.StateChanged(); } catch { } }
    static void StartThread(string name, Action a) => new Thread(() => a()) { IsBackground = true, Name = "LanDrop " + name }.Start();
    static string NewCode() => RandomNumberGenerator.GetInt32(0, 1000000).ToString("D6");
    bool TryBegin() => Interlocked.CompareExchange(ref busyFlag, 1, 0) == 0;

    void EndBusy()
    {
        activity = Activity.None;
        offerSummary = null;
        Interlocked.Exchange(ref busyFlag, 0);
        Changed();
    }

    void BeginTransfer(string verb, long total, int count)
    {
        TotalBytes = total;
        FileCount = count;
        Interlocked.Exchange(ref doneBytes, 0);
        Interlocked.Exchange(ref fileNumber, 0);
        currentFile = "";
        if (Interlocked.Exchange(ref transferFlag, 1) == 0) KeepAwake.Begin();
        try { host.TransferStarted(verb, total, count); } catch { }
    }

    void EndTransfer(TransferResult r)
    {
        if (Interlocked.Exchange(ref transferFlag, 0) == 1) KeepAwake.End();
        try { host.TransferEnded(r); } catch { }
    }

    // ---------- waiting for a connection ----------

    // Returns null when waiting started, or a message saying why it couldn't.
    public string StartHosting(string code = null)
    {
        lock (gate) if (conn != null || listener != null || connecting) return "Already connected or waiting.";
        X509Certificate2 cert;
        try { cert = Util.MakeCert(); }
        catch (Exception ex) { return "Couldn't set up encryption: " + ex.Message; }
        TcpListener l;
        try
        {
            l = new TcpListener(opt.Loopback ? IPAddress.Loopback : IPAddress.Any, opt.Port);
            l.Start();
        }
        catch (Exception ex) { return "Couldn't start waiting for a connection on port " + opt.Port + ": " + ex.Message; }
        byte[] secret = Util.RandomBytes(16);
        string pc = code ?? NewCode();
        lock (gate)
        {
            listener = l;
            pairCode = pc;
            inviteKey = null;
        }
        try { host.CodeChanged(pc); } catch { }
        Log("Waiting for a connection on port " + opt.Port + ".");
        Changed();
        StartThread("accept", () => AcceptLoop(l, cert, secret));
        StartThread("invite", () =>
        {
            var inv = new Invite { Port = opt.Port, Fingerprint = Util.Sha256(cert.RawData), Secret = secret };
            string pub = null;
            if (opt.Loopback) inv.Addresses.Add(IPAddress.Loopback);
            else
            {
                pub = Util.PublicAddress();
                if (pub != null) inv.Addresses.Add(IPAddress.Parse(pub));
                foreach (var a in Util.LocalAddresses().Take(4)) inv.Addresses.Add(IPAddress.Parse(a));
            }
            string key = inv.Encode();
            lock (gate)
            {
                publicAddress = pub;
                if (listener != l) return;
                inviteKey = key;
            }
            try { host.InviteReady(key, pub); } catch { }
            if (pub == null && !opt.Loopback)
                Log("Couldn't find this computer's internet address, so this invite key only works on this network.");
        });
        return null;
    }

    public void StopHosting()
    {
        TcpListener l;
        lock (gate)
        {
            l = listener;
            listener = null;
            pairCode = null;
            inviteKey = null;
        }
        if (l == null) return;
        try { l.Stop(); } catch { }
        Changed();
    }

    void AcceptLoop(TcpListener l, X509Certificate2 cert, byte[] secret)
    {
        int wrong = 0;
        while (true)
        {
            TcpClient c;
            try { c = l.AcceptTcpClient(); }
            catch { return; } // stopped
            Connection cn = null;
            SslStream ssl = null;
            try
            {
                var ep = (IPEndPoint)c.Client.RemoteEndPoint;
                var ip = ep.Address.IsIPv4MappedToIPv6 ? ep.Address.MapToIPv4() : ep.Address;
                bool local = !opt.PublicOnly && Util.IsLocal(ip);
                Connection.Prepare(c);
                ssl = new SslStream(c.GetStream(), false);
                ssl.AuthenticateAsServer(new SslServerAuthenticationOptions
                {
                    ServerCertificate = cert,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.None, // let the system pick (TLS 1.2 or 1.3)
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                });
                cn = new Connection(c, ssl);
                if (cn.Reader.ReadString() != Magic) { cn.Dispose(); continue; }
                byte kind = cn.Reader.ReadByte();
                string why = null;
                if (kind == AuthKey)
                {
                    if (!Util.SameBytes(cn.Reader.ReadBytes(16), secret))
                        why = "That invite key doesn't match. It may be from an earlier session: ask for a new one.";
                }
                else if (kind == AuthCode)
                {
                    string code = cn.Reader.ReadString().Replace(" ", "").Trim();
                    if (!local)
                        why = "From outside " + opt.MachineName + "'s network, connect with the invite key instead of the code.";
                    else if (code != pairCode)
                    {
                        why = "That code is wrong. Check the code shown on " + opt.MachineName + ".";
                        if (++wrong >= 5)
                        {
                            wrong = 0;
                            string nc = NewCode();
                            lock (gate) if (listener == l) pairCode = nc;
                            try { host.CodeChanged(nc); } catch { }
                            Log("Too many wrong codes, so the code was changed.");
                        }
                    }
                }
                else { cn.Dispose(); continue; }
                string name = cn.Reader.ReadString();
                if (why != null)
                {
                    string w2 = why;
                    cn.Send(w => { w.Write(false); w.Write(w2); });
                    cn.Dispose();
                    Log("Turned away a connection from " + ip + ": " + why);
                    continue;
                }
                cn.Send(w => { w.Write(true); w.Write(opt.MachineName); });
                cn.ReceiveTimeout = 0;
                cn.PeerName = name;
            }
            catch
            {
                if (cn != null) cn.Dispose();
                else
                {
                    try { ssl?.Dispose(); } catch { }
                    c.Dispose();
                }
                continue;
            }
            lock (gate)
            {
                if (listener != l || disposed) { cn.Dispose(); return; } // stopped waiting meanwhile
                listener = null;
                pairCode = null;
                inviteKey = null;
                try { l.Stop(); } catch { }
                conn = cn;
                userDisconnect = false;
            }
            OnConnected(cn);
            return;
        }
    }

    // ---------- connecting ----------

    // input is an address or an invite key. Returns null when connecting started, or a message saying why not.
    // The outcome arrives later through StateChanged (connected) or ConnectFailed.
    public string Connect(string input, string code)
    {
        input = (input ?? "").Trim();
        code = (code ?? "").Replace(" ", "").Trim();
        Invite inv = null;
        if (Invite.LooksLikeKey(input))
        {
            inv = Invite.TryParse(input);
            if (inv == null) return "That invite key is incomplete or damaged. Copy the whole key again (it starts with LD1-).";
        }
        else if (input == "" || code == "")
            return "On the same network: enter the other computer's address and the code it shows.\nOver the internet: paste the invite key it shows into the first box.";
        lock (gate)
        {
            if (conn != null || listener != null || connecting) return "Already connected or waiting.";
            connecting = true;
        }
        Changed();
        StartThread("connect", () => ConnectWorker(input, code, inv));
        return null;
    }

    void ConnectWorker(string addr, string code, Invite inv)
    {
        string target = inv != null ? "the computer in the invite key" : addr;
        const string hint = "\n\nCheck that LAN Drop on the other computer is still waiting for a connection.";
        TcpClient c = null;
        Connection cn = null;
        try
        {
            if (inv != null)
            {
                c = Util.ConnectAny(inv.Addresses, inv.Port, 10000);
                if (c == null)
                    throw new Exception("No answer from " + string.Join(", ", inv.Addresses) + " on port " + inv.Port + "." + hint
                        + " If it's on another network, its router must forward port " + inv.Port + " to it.");
            }
            else
            {
                c = new TcpClient(AddressFamily.InterNetwork);
                using var cts = new CancellationTokenSource(8000);
                try { c.ConnectAsync(addr, opt.Port, cts.Token).AsTask().GetAwaiter().GetResult(); }
                catch (OperationCanceledException) { throw new Exception("No answer from " + addr + "." + hint + " Also check the address."); }
            }
            Connection.Prepare(c);
            // With an invite key, only the exact computer that made the key is accepted.
            var ssl = new SslStream(c.GetStream(), false, (s, cert, chain, errors) =>
                inv == null || (cert != null && Util.SameBytes(Util.Sha256(cert.GetRawCertData()), inv.Fingerprint)));
            try
            {
                ssl.AuthenticateAsClient(new SslClientAuthenticationOptions
                {
                    TargetHost = "landrop",
                    EnabledSslProtocols = SslProtocols.None,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                });
            }
            catch (AuthenticationException)
            {
                throw new Exception("The computer that answered isn't the one that made this invite key. The key may be from an earlier session: ask for a new one.");
            }
            cn = new Connection(c, ssl);
            cn.Send(w =>
            {
                w.Write(Magic);
                if (inv != null) { w.Write(AuthKey); w.Write(inv.Secret); }
                else { w.Write(AuthCode); w.Write(code); }
                w.Write(opt.MachineName);
            });
            bool ok = cn.Reader.ReadBoolean();
            string info = cn.Reader.ReadString();
            if (!ok) throw new Exception(info);
            cn.ReceiveTimeout = 0;
            cn.PeerName = info;
            lock (gate)
            {
                connecting = false;
                if (disposed) { cn.Dispose(); return; }
                conn = cn;
                userDisconnect = false;
            }
            OnConnected(cn);
        }
        catch (Exception ex)
        {
            if (cn != null) cn.Dispose(); else c?.Dispose();
            string m = ex is SocketException || ex is IOException
                ? "Couldn't connect to " + target + ":\n" + ex.Message + hint
                : ex.Message;
            connecting = false;
            Log("Couldn't connect to " + target + ": " + ex.Message.Split('\n')[0]);
            Changed();
            try { host.ConnectFailed(m); } catch { }
        }
    }

    void OnConnected(Connection cn)
    {
        Log("Connected to " + cn.PeerName + " at " + cn.PeerAddress + ".");
        Changed();
        StartThread("read", () => ReadLoop(cn));
    }

    public void Disconnect()
    {
        userDisconnect = true;
        conn?.Dispose(); // the reader notices and cleans up
    }

    void OnDisconnected(Connection cn, string why)
    {
        lock (gate)
        {
            if (conn != cn) return;
            conn = null;
        }
        cn.Dispose();
        sendCancel = true;
        var act = activity;
        bool wasOffering = act == Activity.Offering;
        outgoing = null;
        if (IsTransferring)
        {
            EndTransfer(new TransferResult
            {
                Sending = act == Activity.Sending,
                ConnectionLost = true,
                Folder = act == Activity.Receiving ? rxRoot : null,
                Summary = act == Activity.Receiving
                    ? "Stopped: the connection was lost. Finished files are saved. Send again and they'll be skipped."
                    : "Stopped: the connection was lost. Send again to pick up where it stopped.",
            });
        }
        else if (wasOffering)
        {
            try { host.TransferEnded(new TransferResult { Sending = true, ConnectionLost = true, Summary = "The connection was lost before the files were accepted." }); } catch { }
        }
        Log(userDisconnect || disposed ? "Disconnected." : "Disconnected: " + why);
        EndBusy();
    }

    // ---------- reading messages ----------

    void ReadLoop(Connection cn)
    {
        string why = "unknown error";
        try
        {
            var r = cn.Reader;
            while (true)
            {
                byte t = r.ReadByte();
                switch (t)
                {
                    case Msg.Offer: HandleOffer(cn, ReadOffer(r)); break;
                    case Msg.Accept:
                        {
                            int id = r.ReadInt32(), n = r.ReadInt32();
                            if (n < 0 || n > 10000000) throw new InvalidDataException("bad accept");
                            var skip = new HashSet<int>();
                            for (int i = 0; i < n; i++) skip.Add(r.ReadInt32());
                            HandleAccept(cn, id, skip);
                            break;
                        }
                    case Msg.Decline: HandleDecline(r.ReadInt32(), r.ReadString()); break;
                    case Msg.FileBegin: RecvFileBegin(cn, r.ReadInt32()); break;
                    case Msg.Chunk:
                        {
                            int len = r.ReadInt32();
                            if (len < 0 || len > ChunkSize) throw new InvalidDataException("bad chunk");
                            Util.ReadFully(r, recvBuf, len);
                            RecvChunk(cn, len);
                            break;
                        }
                    case Msg.FileEnd: RecvFileEnd(cn, r.ReadBytes(32)); break;
                    case Msg.FileAbort: RecvFileAbort(r.ReadString()); break;
                    case Msg.TransferEnd: { int id = r.ReadInt32(); RecvTransferEnd(cn, id, r.ReadBoolean()); break; }
                    case Msg.Cancel:
                        if (activity == Activity.Sending) { sendCancel = true; Log(cn.PeerName + " cancelled the transfer."); }
                        break;
                    case Msg.Result: HandleResult(r); break;
                    default: throw new InvalidDataException("unexpected message " + t);
                }
            }
        }
        catch (EndOfStreamException) { why = cn.PeerName + " closed the connection"; }
        catch (IOException) { why = "the connection to " + cn.PeerName + " was lost"; }
        catch (ObjectDisposedException) { why = "closed"; }
        catch (Exception ex) { why = ex.Message; }
        DiscardRxFile();
        rxOffer = null;
        OnDisconnected(cn, why);
    }

    static Offer ReadOffer(BinaryReader r)
    {
        var o = new Offer { Id = r.ReadInt32() };
        int n = r.ReadInt32();
        if (n < 0 || n > 10000000) throw new InvalidDataException("bad offer");
        for (int i = 0; i < n; i++)
        {
            var it = new OfferItem { RelPath = r.ReadString(), Size = r.ReadInt64() };
            long ticks = r.ReadInt64();
            if (it.Size < 0) throw new InvalidDataException("bad size");
            it.Modified = ticks >= DateTime.MinValue.Ticks && ticks <= DateTime.MaxValue.Ticks ? new DateTime(ticks, DateTimeKind.Utc) : DateTime.MinValue;
            o.Items.Add(it);
            o.Total += it.Size;
        }
        return o;
    }

    // ---------- sending ----------

    // Returns null when the offer is on its way, or a message saying why not.
    public string Offer(IEnumerable<string> paths)
    {
        var cn = conn;
        if (cn == null) return "Connect to the other computer first.";
        if (!TryBegin()) return "Wait for the current transfer to finish first.";
        activity = Activity.Listing;
        Changed();
        var list = paths.ToList();
        StartThread("list", () =>
        {
            var items = new List<OfferItem>();
            var problems = new List<string>();
            foreach (var p in list) Util.AddPath(p, items, problems);
            Util.Dedupe(items);
            foreach (var pr in problems) Log("Left out " + pr);
            if (items.Count == 0)
            {
                Log("Nothing to send: no files found there.");
                EndBusy();
                return;
            }
            var o = new Offer { Id = Interlocked.Increment(ref offerCounter), Items = items, Total = items.Sum(x => x.Size) };
            string what = Util.Count(items.Count, "file", "files") + " (" + Util.Bytes(o.Total) + ")";
            outgoing = o;
            sendCancel = false;
            offerSummary = what;
            activity = Activity.Offering;
            try
            {
                cn.Send(w =>
                {
                    w.Write(Msg.Offer);
                    w.Write(o.Id);
                    w.Write(o.Items.Count);
                    foreach (var it in o.Items) { w.Write(it.RelPath); w.Write(it.Size); w.Write(it.Modified.Ticks); }
                });
            }
            catch (Exception ex)
            {
                outgoing = null;
                Log("Couldn't send the offer: " + ex.Message);
                EndBusy();
                return;
            }
            Log("Offered " + what + " to " + cn.PeerName + ".");
            Changed();
        });
        return null;
    }

    void HandleAccept(Connection cn, int id, HashSet<int> skip)
    {
        var o = outgoing;
        if (o == null || o.Id != id || activity != Activity.Offering)
        {
            // Accepted after we withdrew the offer: tell them it's off.
            cn.Send(w => { w.Write(Msg.TransferEnd); w.Write(id); w.Write(true); });
            return;
        }
        long total = 0;
        int count = 0;
        for (int i = 0; i < o.Items.Count; i++)
            if (!skip.Contains(i)) { total += o.Items[i].Size; count++; }
        sendCancel = false;
        activity = Activity.Sending;
        BeginTransfer("Sending", total, count);
        Changed();
        int skipped = o.Items.Count - count;
        Log(cn.PeerName + " accepted." + (skipped > 0 ? " " + Util.Count(skipped, "file is", "files are") + " already there and will be skipped." : ""));
        StartThread("send", () => SendFiles(cn, o, skip));
    }

    void HandleDecline(int id, string reason)
    {
        var o = outgoing;
        if (o == null || o.Id != id) return;
        outgoing = null;
        string peer = PeerName ?? "The other computer";
        Log(peer + " didn't take the files: " + reason);
        try { host.TransferEnded(new TransferResult { Sending = true, Declined = true, Summary = peer + " didn't take the files: " + reason }); } catch { }
        EndBusy();
    }

    void SendFiles(Connection cn, Offer o, HashSet<int> skip)
    {
        var buf = new byte[ChunkSize];
        bool cancelled = false;
        try
        {
            for (int i = 0; i < o.Items.Count && !cancelled; i++)
            {
                if (skip.Contains(i)) continue;
                if (sendCancel) { cancelled = true; break; }
                var it = o.Items[i];
                currentFile = it.RelPath;
                Interlocked.Increment(ref fileNumber);
                int idx = i;
                cn.Send(w => { w.Write(Msg.FileBegin); w.Write(idx); });
                string err = null;
                long sent = 0;
                using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                {
                    FileStream fs = null;
                    try { fs = new FileStream(it.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan); }
                    catch (Exception ex) { err = "couldn't open it: " + ex.Message; }
                    if (fs != null)
                    {
                        using (fs)
                        {
                            while (sent < it.Size)
                            {
                                if (sendCancel) { cancelled = true; err = "cancelled"; break; }
                                int want = (int)Math.Min(ChunkSize, it.Size - sent);
                                int n;
                                try { n = fs.Read(buf, 0, want); }
                                catch (IOException ex) { err = "read error: " + ex.Message; break; }
                                if (n <= 0) { err = "the file got smaller while it was being sent"; break; }
                                sha.AppendData(buf, 0, n);
                                int len = n;
                                cn.Send(w => { w.Write(Msg.Chunk); w.Write(len); w.Write(buf, 0, len); });
                                sent += n;
                                Interlocked.Add(ref doneBytes, n);
                            }
                        }
                    }
                    if (err == null)
                    {
                        byte[] h = sha.GetHashAndReset();
                        cn.Send(w => { w.Write(Msg.FileEnd); w.Write(h); });
                    }
                    else
                    {
                        string e2 = err;
                        cn.Send(w => { w.Write(Msg.FileAbort); w.Write(e2); });
                        Interlocked.Add(ref doneBytes, it.Size - sent);
                        if (!cancelled) Log("Couldn't send " + it.RelPath + ": " + err);
                    }
                }
            }
            bool c2 = cancelled;
            cn.Send(w => { w.Write(Msg.TransferEnd); w.Write(o.Id); w.Write(c2); });
            if (cancelled) Log("Cancelling…");
        }
        catch (Exception) { /* connection dropped; the reader reports it */ }
    }

    void HandleResult(BinaryReader r)
    {
        int id = r.ReadInt32();
        bool cancelled = r.ReadBoolean();
        int ok = r.ReadInt32(), skipped = r.ReadInt32(), failedTotal = r.ReadInt32(), listed = r.ReadInt32();
        if (listed < 0 || listed > 100000) throw new InvalidDataException("bad result");
        var failed = new List<string>();
        for (int i = 0; i < listed; i++) failed.Add(r.ReadString());
        var o = outgoing;
        if (o == null || o.Id != id) return;
        outgoing = null;
        string peer = PeerName ?? "the other computer";
        string summary = cancelled
            ? "Cancelled. " + Util.Count(ok, "file", "files") + " had already arrived on " + peer + "."
            : "Done. " + Util.Count(ok, "file", "files") + " sent and checked on " + peer
              + (skipped > 0 ? ", " + skipped.ToString("N0") + " already there" : "")
              + (failedTotal > 0 ? ". " + failedTotal.ToString("N0") + " failed" : "") + ".";
        Log(summary);
        foreach (var f in failed) Log("Failed: " + f);
        EndTransfer(new TransferResult { Sending = true, Cancelled = cancelled, Ok = ok, Skipped = skipped, FailedTotal = failedTotal, Failed = failed, Summary = summary });
        EndBusy();
    }

    public void Cancel()
    {
        switch (activity)
        {
            case Activity.Offering:
                outgoing = null;
                Log("You withdrew the offer.");
                try { host.TransferEnded(new TransferResult { Sending = true, Cancelled = true, Summary = "You withdrew the offer." }); } catch { }
                EndBusy();
                break;
            case Activity.Sending:
                sendCancel = true;
                break;
            case Activity.Receiving:
                rxCancelled = true;
                try { conn?.Send(w => w.Write(Msg.Cancel)); } catch { }
                Log("You cancelled the transfer.");
                break;
        }
    }

    // ---------- receiving ----------

    void HandleOffer(Connection cn, Offer offer)
    {
        if (!TryBegin())
        {
            cn.Send(w => { w.Write(Msg.Decline); w.Write(offer.Id); w.Write("it's busy with another transfer. Try again when it's done."); });
            return;
        }
        activity = Activity.Choosing;
        Changed();
        Log(cn.PeerName + " wants to send " + Util.Count(offer.Items.Count, "file", "files") + " (" + Util.Bytes(offer.Total) + ").");
        AcceptChoice choice = null;
        try { choice = host.ChooseIncoming(cn.PeerName, offer); } catch { }
        if (conn != cn) return; // disconnected while deciding
        if (choice == null || string.IsNullOrWhiteSpace(choice.Folder))
        {
            cn.Send(w => { w.Write(Msg.Decline); w.Write(offer.Id); w.Write("they declined."); });
            Log("You declined the files.");
            EndBusy();
            return;
        }
        string folder = Path.GetFullPath(choice.Folder);

        var skip = new List<int>();
        long total = 0;
        int count = 0;
        for (int i = 0; i < offer.Items.Count; i++)
        {
            var it = offer.Items[i];
            bool already = false;
            if (choice.SkipExisting)
            {
                try
                {
                    var fi = new FileInfo(Path.Combine(folder, Util.SafeRelPath(it.RelPath)));
                    already = fi.Exists && fi.Length == it.Size && Math.Abs((fi.LastWriteTimeUtc - it.Modified).TotalSeconds) < 2.1;
                }
                catch { }
            }
            if (already) skip.Add(i); else { total += it.Size; count++; }
        }

        rxOffer = offer;
        rxRoot = folder;
        rxCancelled = false;
        rxOk = 0;
        rxSkipped = skip.Count;
        rxFailed = new List<string>();
        rxIndex = -1;
        activity = Activity.Receiving;
        BeginTransfer("Receiving", total, count);
        Changed();
        cn.Send(w =>
        {
            w.Write(Msg.Accept);
            w.Write(offer.Id);
            w.Write(skip.Count);
            foreach (int s in skip) w.Write(s);
        });
        Log("Receiving " + Util.Count(count, "file", "files") + " (" + Util.Bytes(total) + ") into " + folder
            + (skip.Count > 0 ? ". Skipping " + Util.Count(skip.Count, "file", "files") + " already there." : "."));
    }

    void RecvFileBegin(Connection cn, int index)
    {
        DiscardRxFile();
        if (rxOffer == null || index < 0 || index >= rxOffer.Items.Count) throw new InvalidDataException("unexpected file");
        var it = rxOffer.Items[index];
        rxIndex = index;
        rxWritten = 0;
        rxFileFailed = false;
        currentFile = it.RelPath;
        Interlocked.Increment(ref fileNumber);
        if (rxCancelled) { rxFileFailed = true; return; }
        try
        {
            rxDest = Path.Combine(rxRoot, Util.SafeRelPath(it.RelPath));
            Directory.CreateDirectory(Path.GetDirectoryName(rxDest));
            rxPart = rxDest + ".landrop-part";
            rxStream = new FileStream(rxPart, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16);
            if (it.Size > 0) rxStream.SetLength(it.Size); // reserve the space up front
            rxHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        }
        catch (Exception ex) { RxFail(cn, it, ex); }
    }

    void RecvChunk(Connection cn, int len)
    {
        Interlocked.Add(ref doneBytes, len);
        if (rxFileFailed || rxStream == null) return;
        if (rxCancelled) { DiscardRxFile(); rxFileFailed = true; return; }
        try
        {
            rxStream.Write(recvBuf, 0, len);
            rxHash.AppendData(recvBuf, 0, len);
            rxWritten += len;
        }
        catch (Exception ex) { RxFail(cn, rxOffer.Items[rxIndex], ex); }
    }

    void RecvFileEnd(Connection cn, byte[] hash)
    {
        if (rxOffer == null || rxIndex < 0) return;
        var it = rxOffer.Items[rxIndex];
        if (rxFileFailed || rxStream == null) { DiscardRxFile(); return; }
        try
        {
            bool ok = rxWritten == it.Size && hash.Length == 32 && Util.SameBytes(rxHash.GetHashAndReset(), hash);
            rxStream.Dispose();
            rxStream = null;
            if (!ok)
            {
                DiscardRxFile();
                rxFailed.Add(it.RelPath + ": the check didn't match, so it was thrown away");
                return;
            }
            string final = File.Exists(rxDest) || Directory.Exists(rxDest) ? Util.UniqueName(rxDest) : rxDest;
            File.Move(rxPart, final);
            rxPart = null;
            if (it.Modified != DateTime.MinValue) try { File.SetLastWriteTimeUtc(final, it.Modified); } catch { }
            rxOk++;
        }
        catch (Exception ex) { RxFail(cn, it, ex); }
        finally { DiscardRxFile(); }
    }

    void RecvFileAbort(string reason)
    {
        DiscardRxFile();
        if (rxOffer != null && rxIndex >= 0 && !rxCancelled && reason != "cancelled")
            rxFailed.Add(rxOffer.Items[rxIndex].RelPath + ": on the sending computer, " + reason);
    }

    void RxFail(Connection cn, OfferItem it, Exception ex)
    {
        DiscardRxFile();
        rxFileFailed = true;
        rxFailed.Add(it.RelPath + ": " + ex.Message);
        if (Util.IsDiskFull(ex) && !rxCancelled)
        {
            rxCancelled = true;
            Log("The disk is full, so the transfer was stopped.");
            try { cn.Send(w => w.Write(Msg.Cancel)); } catch { }
        }
    }

    void DiscardRxFile()
    {
        if (rxStream != null) { try { rxStream.Dispose(); } catch { } rxStream = null; }
        if (rxHash != null) { try { rxHash.Dispose(); } catch { } rxHash = null; }
        if (rxPart != null) { try { File.Delete(rxPart); } catch { } rxPart = null; }
    }

    void RecvTransferEnd(Connection cn, int id, bool cancelled)
    {
        DiscardRxFile();
        if (rxOffer == null || rxOffer.Id != id) return;
        bool wasCancelled = cancelled || rxCancelled;
        int ok = rxOk, skipped = rxSkipped;
        var failed = rxFailed;
        var listed = failed.Take(500).ToList();
        cn.Send(w =>
        {
            w.Write(Msg.Result);
            w.Write(id);
            w.Write(wasCancelled);
            w.Write(ok);
            w.Write(skipped);
            w.Write(failed.Count);
            w.Write(listed.Count);
            foreach (var f in listed) w.Write(f);
        });
        string root = rxRoot;
        rxOffer = null;
        string summary = wasCancelled
            ? "Cancelled. " + Util.Count(ok, "file", "files") + " had finished and are saved."
            : "Done. " + Util.Count(ok, "file", "files") + " received and checked"
              + (skipped > 0 ? ", " + skipped.ToString("N0") + " already there" : "")
              + (failed.Count > 0 ? ". " + failed.Count.ToString("N0") + " failed" : "") + ".";
        Log(summary + " Saved in " + root);
        foreach (var f in failed) Log("Failed: " + f);
        EndTransfer(new TransferResult { Cancelled = wasCancelled, Ok = ok, Skipped = skipped, FailedTotal = failed.Count, Failed = failed, Folder = root, Summary = summary });
        EndBusy();
    }

    public void Dispose()
    {
        disposed = true;
        StopHosting();
        var c = conn;
        c?.Dispose();
        if (Interlocked.Exchange(ref transferFlag, 0) == 1) KeepAwake.End();
    }
}
