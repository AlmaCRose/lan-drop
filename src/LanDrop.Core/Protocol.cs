using System.Net;

namespace LanDrop.Core;

// Message types on the wire. These match LAN Drop 2 for Windows, so both can talk to each other.
static class Msg
{
    public const byte Offer = 1, Accept = 2, Decline = 3, FileBegin = 4, Chunk = 5, FileEnd = 6,
        TransferEnd = 7, Cancel = 8, Result = 9, FileAbort = 10;
}

public sealed class OfferItem
{
    public string RelPath;    // always uses '/' between folders
    public long Size;
    public DateTime Modified; // UTC
    public string FullPath;   // sender only
}

public sealed class Offer
{
    public int Id;
    public List<OfferItem> Items = new();
    public long Total;
}

// What the waiting PC hands out for connections from outside its network:
// where to reach it, the fingerprint of its certificate, and a one-time secret.
public sealed class Invite
{
    const string Prefix = "LD1-";
    public int Port;
    public List<IPAddress> Addresses = new();
    public byte[] Fingerprint; // SHA-256 of the waiting PC's certificate
    public byte[] Secret;      // 16 random bytes

    public string Encode()
    {
        var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write((ushort)Port);
        w.Write((byte)Addresses.Count);
        foreach (var a in Addresses) w.Write(a.GetAddressBytes());
        w.Write(Fingerprint);
        w.Write(Secret);
        w.Flush();
        return Prefix + Convert.ToBase64String(ms.ToArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static bool LooksLikeKey(string s) =>
        s != null && s.Trim().StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);

    public static Invite TryParse(string s)
    {
        if (!LooksLikeKey(s)) return null;
        s = new string(s.Where(ch => !char.IsWhiteSpace(ch)).ToArray());
        try
        {
            string b = s.Substring(Prefix.Length).Replace('-', '+').Replace('_', '/');
            while (b.Length % 4 != 0) b += "=";
            var data = Convert.FromBase64String(b);
            var r = new BinaryReader(new MemoryStream(data));
            var inv = new Invite { Port = r.ReadUInt16() };
            int n = r.ReadByte();
            if (n < 1 || n > 8) return null;
            for (int i = 0; i < n; i++) inv.Addresses.Add(new IPAddress(r.ReadBytes(4)));
            inv.Fingerprint = r.ReadBytes(32);
            inv.Secret = r.ReadBytes(16);
            if (inv.Fingerprint.Length != 32 || inv.Secret.Length != 16 || r.BaseStream.Position != data.Length) return null;
            return inv;
        }
        catch { return null; }
    }
}

public sealed class PeerOptions
{
    public int Port = Peer.DefaultPort;
    public bool Loopback;     // listen on 127.0.0.1 only, and put only that in invite keys (tests)
    public bool PublicOnly;   // treat every caller as outside the network (tests)
    public string MachineName = Environment.MachineName;
}

public sealed class AcceptChoice
{
    public string Folder;
    public bool SkipExisting = true;
}

public sealed class TransferResult
{
    public bool Sending;      // reported on the sending side
    public bool Declined, Cancelled, ConnectionLost;
    public int Ok, Skipped, FailedTotal;
    public List<string> Failed = new();
    public string Folder;     // receiving side: where the files went
    public string Summary;
    public bool Complete => !Declined && !Cancelled && !ConnectionLost && FailedTotal == 0;
}

// What the app (or a test) provides. Every call comes from a background thread.
public interface IPeerHost
{
    void Log(string message);
    void StateChanged();
    void CodeChanged(string code);
    void InviteReady(string key, string publicAddress);
    void ConnectFailed(string message);
    // Blocks until the person decides. Return null to decline.
    AcceptChoice ChooseIncoming(string peerName, Offer offer);
    void TransferStarted(string verb, long totalBytes, int fileCount);
    void TransferEnded(TransferResult result);
}
