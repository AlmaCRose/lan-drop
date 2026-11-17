// LAN Drop: send files between two Windows PCs on the same network.
// One PC waits for a connection and shows a code; the other connects with that code.
// Either side drops files, the other side accepts or declines. Every file is SHA-256 checked.
// Build with build.bat (uses the C# compiler that ships with Windows; C# 5 syntax only).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyTitle("LAN Drop")]
[assembly: System.Reflection.AssemblyProduct("LAN Drop")]
[assembly: System.Reflection.AssemblyVersion("2.0.0.0")]
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.8")]

namespace LanDrop
{
    static class Program
    {
        [DllImport("user32.dll")]
        static extern bool SetProcessDPIAware();

        [STAThread]
        static int Main(string[] args)
        {
            try { SetProcessDPIAware(); } catch { }
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(Options.Parse(args)));
            return Environment.ExitCode;
        }
    }

    // Flags used only by the automated test; normal use has none.
    class Options
    {
        public int Port = 50505;
        public bool Loopback;
        public string HostCode, Connect, Code, Send, AcceptTo, LogFile, InviteFile;
        public bool ExitWhenDone, PublicOnly;

        public static Options Parse(string[] a)
        {
            var o = new Options();
            try
            {
                for (int i = 0; i < a.Length; i++)
                {
                    switch (a[i])
                    {
                        case "--test-port": o.Port = int.Parse(a[++i]); break;
                        case "--test-loopback": o.Loopback = true; break;
                        case "--test-host": o.HostCode = a[++i]; break;
                        case "--test-connect": o.Connect = a[++i]; o.Code = a[++i]; break;
                        case "--test-send": o.Send = a[++i]; break;
                        case "--test-accept": o.AcceptTo = a[++i]; break;
                        case "--test-exit": o.ExitWhenDone = true; break;
                        case "--test-log": o.LogFile = a[++i]; break;
                        case "--test-invite-file": o.InviteFile = a[++i]; break;   // host writes its invite key here
                        case "--test-public-only": o.PublicOnly = true; break;     // host treats every caller as outside the network
                    }
                }
            }
            catch { }
            return o;
        }
    }

    static class Msg
    {
        public const byte Offer = 1, Accept = 2, Decline = 3, FileBegin = 4, Chunk = 5, FileEnd = 6,
            TransferEnd = 7, Cancel = 8, Result = 9, FileAbort = 10;
    }

    class OfferItem
    {
        public string RelPath;   // always uses '/' between folders
        public long Size;
        public DateTime Modified; // UTC
        public string FullPath;  // sender only
    }

    class Offer
    {
        public int Id;
        public List<OfferItem> Items = new List<OfferItem>();
        public long Total;
    }

    class Connection : IDisposable
    {
        readonly TcpClient client;
        public readonly BinaryReader Reader;
        readonly BinaryWriter writer;
        readonly object writeLock = new object();
        public string PeerName = "the other PC";
        public readonly string PeerAddress;

        // Socket settings applied before the TLS handshake.
        public static void Prepare(TcpClient c)
        {
            c.NoDelay = true;
            c.ReceiveBufferSize = 1 << 20;
            c.SendBufferSize = 1 << 20;
            c.ReceiveTimeout = 15000; // handshake must finish in time; cleared once connected
            try
            {
                // Notice a dead link within about 30 seconds instead of 2 hours.
                var ka = new byte[12];
                BitConverter.GetBytes(1).CopyTo(ka, 0);
                BitConverter.GetBytes(15000).CopyTo(ka, 4);
                BitConverter.GetBytes(3000).CopyTo(ka, 8);
                c.Client.IOControl(IOControlCode.KeepAliveValues, ka, null);
            }
            catch { }
        }

        // s is the TLS stream on top of c.
        public Connection(TcpClient c, Stream s)
        {
            client = c;
            Reader = new BinaryReader(new BufferedStream(s, 1 << 16), Encoding.UTF8);
            writer = new BinaryWriter(new BufferedStream(s, 1 << 16), Encoding.UTF8);
            PeerAddress = ((IPEndPoint)c.Client.RemoteEndPoint).Address.ToString();
        }

        public int ReceiveTimeout { set { client.ReceiveTimeout = value; } }

        public void Send(Action<BinaryWriter> write)
        {
            lock (writeLock)
            {
                write(writer);
                writer.Flush();
            }
        }

        public void Dispose()
        {
            try { client.Close(); } catch { }
        }
    }

    // What the waiting PC hands out for connections from outside its network:
    // where to reach it, the fingerprint of its certificate, and a one-time secret.
    class Invite
    {
        const string Prefix = "LD1-";
        public int Port;
        public List<IPAddress> Addresses = new List<IPAddress>();
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

        public static bool LooksLikeKey(string s)
        {
            return s != null && s.Trim().StartsWith(Prefix, StringComparison.OrdinalIgnoreCase);
        }

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

    static class Util
    {
        public static byte[] Sha256(byte[] data)
        {
            using (var h = new SHA256Cng()) return h.ComputeHash(data);
        }

        public static byte[] RandomBytes(int n)
        {
            var b = new byte[n];
            using (var r = new RNGCryptoServiceProvider()) r.GetBytes(b);
            return b;
        }

        public static bool SameBytes(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        // A throwaway certificate for this session's TLS. Nobody trusts it by name;
        // the invite key carries its fingerprint instead.
        public static X509Certificate2 MakeCert()
        {
            using (var rsa = new RSACng(2048))
            {
                var req = new CertificateRequest("CN=LAN Drop", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                using (var tmp = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30)))
                {
                    // Windows TLS can't use the in-memory key directly; a round trip through PFX fixes that.
                    return new X509Certificate2(tmp.Export(X509ContentType.Pfx, "landrop"), "landrop", X509KeyStorageFlags.UserKeySet);
                }
            }
        }

        // Addresses on this side of a home router (or a Tailscale-style VPN).
        public static bool IsLocal(IPAddress ip)
        {
            if (IPAddress.IsLoopback(ip)) return true;
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (ip.AddressFamily != AddressFamily.InterNetwork) return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal;
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
        }

        // This network's address on the internet, as seen from outside. Null if it can't be found.
        public static string PublicAddress()
        {
            foreach (var url in new[] { "https://api.ipify.org", "https://icanhazip.com" })
            {
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create(url);
                    req.Timeout = 6000;
                    req.ReadWriteTimeout = 6000;
                    req.UserAgent = "LAN Drop";
                    using (var resp = req.GetResponse())
                    using (var sr = new StreamReader(resp.GetResponseStream()))
                    {
                        string s = sr.ReadToEnd().Trim();
                        IPAddress ip;
                        if (IPAddress.TryParse(s, out ip) && ip.AddressFamily == AddressFamily.InterNetwork && !IsLocal(ip)) return s;
                    }
                }
                catch { }
            }
            return null;
        }

        // Tries every address at once and keeps the first that answers.
        public static TcpClient ConnectAny(List<IPAddress> addrs, int port, int timeoutMs)
        {
            var clients = new List<TcpClient>();
            var results = new List<IAsyncResult>();
            foreach (var a in addrs)
            {
                var c = new TcpClient(AddressFamily.InterNetwork);
                clients.Add(c);
                results.Add(c.BeginConnect(a, port, null, null));
            }
            var sw = Stopwatch.StartNew();
            var pending = Enumerable.Range(0, clients.Count).ToList();
            TcpClient winner = null;
            while (winner == null && pending.Count > 0)
            {
                long left = timeoutMs - sw.ElapsedMilliseconds;
                if (left <= 0) break;
                int k = WaitHandle.WaitAny(pending.Select(i => results[i].AsyncWaitHandle).ToArray(), (int)left);
                if (k == WaitHandle.WaitTimeout) break;
                int idx = pending[k];
                pending.RemoveAt(k);
                try { clients[idx].EndConnect(results[idx]); winner = clients[idx]; }
                catch { }
            }
            foreach (var c in clients) if (c != winner) try { c.Close(); } catch { }
            return winner;
        }

        public static string Bytes(long b)
        {
            if (b < 1024) return b + " B";
            double v = b;
            string[] units = { "KB", "MB", "GB", "TB" };
            int i = -1;
            do { v /= 1024; i++; } while (v >= 1024 && i < units.Length - 1);
            return v.ToString(v >= 100 ? "0" : "0.0") + " " + units[i];
        }

        public static string Count(int n, string one, string many)
        {
            return n.ToString("N0") + " " + (n == 1 ? one : many);
        }

        public static string Duration(double s)
        {
            if (s < 60) return Math.Max(1, (int)s) + " sec";
            if (s < 3600) return (int)(s / 60) + " min";
            return (int)(s / 3600) + " hr " + (int)((s % 3600) / 60) + " min";
        }

        static readonly char[] Invalid = Path.GetInvalidFileNameChars();
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
            return string.Join("\\", parts);
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
            int code = ex.HResult & 0xFFFF;
            return code == 0x70 || code == 0x27;
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
                        if (s.StartsWith("169.254.")) continue;
                        list.Add(s);
                    }
                }
            }
            catch { }
            return list;
        }

        public static void AddPath(string path, List<OfferItem> items, List<string> problems)
        {
            if (path.Length > 3) path = path.TrimEnd('\\', '/');
            try
            {
                if (File.Exists(path))
                {
                    var fi = new FileInfo(path);
                    items.Add(new OfferItem { FullPath = fi.FullName, RelPath = fi.Name, Size = fi.Length, Modified = fi.LastWriteTimeUtc });
                }
                else if (Directory.Exists(path))
                {
                    var di = new DirectoryInfo(path);
                    string name = di.Parent == null ? "Drive " + di.Name.TrimEnd('\\', ':') : di.Name;
                    Walk(di, name, items, problems);
                }
                else problems.Add(path + ": not found");
            }
            catch (Exception ex) { problems.Add(path + ": " + ex.Message); }
        }

        static void Walk(DirectoryInfo dir, string rel, List<OfferItem> items, List<string> problems)
        {
            FileSystemInfo[] entries;
            try { entries = dir.GetFileSystemInfos(); }
            catch (Exception ex) { problems.Add(rel + ": " + ex.Message); return; }
            foreach (var e in entries)
            {
                string r = rel + "/" + e.Name;
                if ((e.Attributes & FileAttributes.Directory) != 0)
                {
                    if ((e.Attributes & FileAttributes.ReparsePoint) != 0) { problems.Add(r + ": a link to another folder, left out"); continue; }
                    Walk((DirectoryInfo)e, r, items, problems);
                }
                else
                {
                    var f = (FileInfo)e;
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
    }

    class MainForm : Form
    {
        const int ChunkSize = 1 << 20;
        const int ModeNone = 0, ModeListing = 1, ModeOffering = 2, ModeSending = 3, ModeChoosing = 4, ModeReceiving = 5;

        [DllImport("kernel32.dll")]
        static extern uint SetThreadExecutionState(uint flags);
        const uint EsContinuous = 0x80000000, EsSystemRequired = 0x00000001;

        readonly Options opt;

        Label lblMe, lblCode, lblCodeCap, lblStatus, lblDrop, lblTransfer, lblStats;
        Button btnHost, btnConnect, btnDisconnect, btnAddFiles, btnAddFolder, btnCancel, btnOpen, btnCopy;
        TextBox txtAddress, txtCode, txtInvite;
        Panel dropPanel;
        ProgressBar progress;
        ListBox log;
        System.Windows.Forms.Timer uiTimer;

        // Connection
        TcpListener listener;
        volatile Connection conn;
        volatile string pairCode;
        bool connecting, userDisconnect, closingForTest;

        // Transfer, shared
        int busyFlag;
        volatile int mode;
        long doneBytes, totalBytes;
        int fileNumber, fileCount;
        volatile string currentFile = "";
        bool progressActive;
        string progressVerb;
        readonly Stopwatch watch = new Stopwatch();
        readonly Queue<KeyValuePair<double, long>> samples = new Queue<KeyValuePair<double, long>>();
        readonly object logFileLock = new object();

        // Sending
        int offerCounter;
        volatile Offer outgoing;
        volatile bool sendCancel;

        // Receiving (touched only by the reader thread, except rxCancelled)
        Offer rxOffer;
        string rxRoot, lastReceivedFolder;
        volatile bool rxCancelled;
        int rxIndex = -1, rxOk, rxSkipped;
        List<string> rxFailed = new List<string>();
        FileStream rxStream;
        HashAlgorithm rxHash;
        string rxPart, rxDest;
        long rxWritten;
        bool rxFileFailed;
        readonly byte[] recvBuf = new byte[ChunkSize];

        public MainForm(Options options)
        {
            opt = options;
            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Segoe UI", 9F);
            Text = "LAN Drop";
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(600, 680);

            var grp = Place(this, new GroupBox { Text = "Connection" }, 12, 8, 576, 220);
            lblMe = Place(grp, new Label(), 12, 24, 552, 20);
            ShowMe(null);
            btnHost = Place(grp, new Button { Text = "Wait for connection" }, 12, 50, 170, 32);
            lblCode = Place(grp, new Label { Font = new Font("Segoe UI", 13F, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft }, 192, 50, 372, 32);
            Place(grp, new Label { Text = "Invite key:" }, 12, 93, 72, 20);
            txtInvite = Place(grp, new TextBox { ReadOnly = true }, 84, 90, 352, 24);
            btnCopy = Place(grp, new Button { Text = "Copy key", Enabled = false }, 444, 88, 120, 28);
            Place(grp, new Label { Text = "Connect to:" }, 12, 135, 72, 20);
            txtAddress = Place(grp, new TextBox(), 84, 132, 220, 24);
            lblCodeCap = Place(grp, new Label { Text = "Code:" }, 312, 135, 40, 20);
            txtCode = Place(grp, new TextBox { MaxLength = 12 }, 352, 132, 84, 24);
            btnConnect = Place(grp, new Button { Text = "Connect" }, 444, 130, 120, 28);
            Place(grp, new Label { Text = "Same network: the other PC's address and code.  Over the internet: paste its invite key.", ForeColor = SystemColors.GrayText }, 12, 160, 552, 18);
            lblStatus = Place(grp, new Label { Text = "Not connected", AutoEllipsis = true }, 12, 188, 420, 20);
            btnDisconnect = Place(grp, new Button { Text = "Disconnect" }, 444, 183, 120, 28);

            dropPanel = Place(this, new Panel { BorderStyle = BorderStyle.FixedSingle, AllowDrop = true }, 12, 238, 576, 120);
            lblDrop = new Label { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleCenter, AllowDrop = true, Font = new Font("Segoe UI", 10F) };
            dropPanel.Controls.Add(lblDrop);
            btnAddFiles = Place(this, new Button { Text = "Add files…" }, 12, 364, 120, 28);
            btnAddFolder = Place(this, new Button { Text = "Add folder…" }, 138, 364, 120, 28);

            lblTransfer = Place(this, new Label { AutoEllipsis = true }, 12, 404, 576, 20);
            progress = Place(this, new ProgressBar { Maximum = 1000 }, 12, 426, 576, 22);
            lblStats = Place(this, new Label(), 12, 454, 330, 20);
            btnOpen = Place(this, new Button { Text = "Open folder", Visible = false }, 342, 450, 120, 28);
            btnCancel = Place(this, new Button { Text = "Cancel" }, 468, 450, 120, 28);
            log = Place(this, new ListBox { HorizontalScrollbar = true, IntegralHeight = false }, 12, 488, 576, 180);

            btnCopy.Click += delegate
            {
                if (txtInvite.Text == "") return;
                try { Clipboard.SetText(txtInvite.Text); Log("Invite key copied. Send it to the other person (Discord, text, email)."); }
                catch (Exception ex) { MessageBox.Show(this, "Couldn't copy: " + ex.Message, "LAN Drop"); }
            };
            txtAddress.TextChanged += delegate { UpdateUi(); };
            txtAddress.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter && Invite.LooksLikeKey(txtAddress.Text)) { e.SuppressKeyPress = true; StartConnect(); } };
            btnHost.Click += delegate { if (listener != null) StopHosting(); else StartHosting(null); };
            btnConnect.Click += delegate { StartConnect(); };
            txtCode.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) { e.SuppressKeyPress = true; StartConnect(); } };
            btnDisconnect.Click += delegate { Disconnect(); };
            btnCancel.Click += delegate { CancelTransfer(); };
            btnOpen.Click += delegate { if (lastReceivedFolder != null) try { Process.Start("explorer.exe", "\"" + lastReceivedFolder + "\""); } catch { } };
            btnAddFiles.Click += delegate
            {
                using (var d = new OpenFileDialog { Multiselect = true, Title = "Choose files to send" })
                    if (d.ShowDialog(this) == DialogResult.OK) StartOffer(d.FileNames);
            };
            btnAddFolder.Click += delegate
            {
                using (var d = new FolderBrowserDialog { Description = "Choose a folder to send. The folder itself and everything in it will be sent." })
                    if (d.ShowDialog(this) == DialogResult.OK) StartOffer(new[] { d.SelectedPath });
            };
            DragEventHandler enter = (s, e) =>
            {
                e.Effect = conn != null && !Busy && e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
            };
            DragEventHandler drop = (s, e) =>
            {
                var paths = e.Data.GetData(DataFormats.FileDrop) as string[];
                if (paths != null && paths.Length > 0) StartOffer(paths);
            };
            dropPanel.DragEnter += enter; dropPanel.DragDrop += drop;
            lblDrop.DragEnter += enter; lblDrop.DragDrop += drop;

            uiTimer = new System.Windows.Forms.Timer { Interval = 250 };
            uiTimer.Tick += delegate { Tick(); };
            uiTimer.Start();

            ResumeLayout(false);
            UpdateUi();
        }

        static T Place<T>(Control parent, T c, int x, int y, int w, int h) where T : Control
        {
            c.SetBounds(x, y, w, h);
            parent.Controls.Add(c);
            return c;
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (opt.HostCode != null) StartHosting(opt.HostCode);
            else if (opt.Connect != null)
            {
                txtAddress.Text = opt.Connect;
                txtCode.Text = opt.Code;
                StartConnect();
            }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!closingForTest && Busy && e.CloseReason == CloseReason.UserClosing &&
                MessageBox.Show(this, "A transfer is in progress. Quit anyway?", "LAN Drop", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            {
                e.Cancel = true;
                return;
            }
            closingForTest = true; // stop reacting to the disconnect below
            StopHosting();
            var c = conn;
            conn = null;
            if (c != null) c.Dispose();
            SetThreadExecutionState(EsContinuous);
            base.OnFormClosing(e);
        }

        // ---------- helpers ----------

        bool Busy { get { return Thread.VolatileRead(ref busyFlag) != 0; } }
        bool TryBegin() { return Interlocked.CompareExchange(ref busyFlag, 1, 0) == 0; }
        void EndBusy() { Interlocked.Exchange(ref busyFlag, 0); UI(UpdateUi); }

        void UI(Action a)
        {
            try
            {
                if (IsDisposed || !IsHandleCreated) return;
                if (InvokeRequired) BeginInvoke(a); else a();
            }
            catch (InvalidOperationException) { } // includes ObjectDisposedException
        }

        bool UISync(Action a)
        {
            try
            {
                if (IsDisposed) return false;
                if (InvokeRequired) Invoke(a); else a();
                return true;
            }
            catch (InvalidOperationException) { return false; }
        }

        void Log(string s)
        {
            string line = DateTime.Now.ToString("HH:mm:ss") + "  " + s;
            if (opt.LogFile != null)
                lock (logFileLock) { try { File.AppendAllText(opt.LogFile, line + Environment.NewLine); } catch { } }
            UI(() => { log.Items.Add(line); log.TopIndex = Math.Max(0, log.Items.Count - 1); });
        }

        string Peer { get { var c = conn; return c != null ? c.PeerName : "the other PC"; } }

        void TestExit(bool success)
        {
            if (!opt.ExitWhenDone) return;
            UI(() => { closingForTest = true; Environment.ExitCode = success ? 0 : 1; Close(); });
        }

        void UpdateUi()
        {
            bool connected = conn != null, hosting = listener != null;
            btnHost.Enabled = !connected && !connecting;
            btnHost.Text = hosting ? "Stop waiting" : "Wait for connection";
            txtAddress.Enabled = btnConnect.Enabled = !connected && !hosting && !connecting;
            bool key = Invite.LooksLikeKey(txtAddress.Text);
            txtCode.Enabled = txtAddress.Enabled && !key;
            lblCodeCap.Enabled = !key;
            btnDisconnect.Enabled = connected;
            bool canSend = connected && !Busy;
            btnAddFiles.Enabled = btnAddFolder.Enabled = canSend;
            dropPanel.BackColor = canSend ? Color.FromArgb(230, 241, 255) : SystemColors.ControlLight;
            lblDrop.ForeColor = canSend ? Color.FromArgb(20, 60, 120) : SystemColors.GrayText;
            lblDrop.Text = !connected ? "Connect to the other PC first.\nThen drop files or folders here to send them."
                : Busy ? "A transfer is in progress."
                : "Drop files or folders here to send them to " + Peer + ".";
            int m = mode;
            btnCancel.Enabled = m == ModeOffering || m == ModeSending || m == ModeReceiving;
            Text = connected ? "LAN Drop - connected to " + Peer : "LAN Drop";
        }

        // ---------- progress ----------

        void BeginProgress(string verb, long total, int count)
        {
            progressVerb = verb;
            totalBytes = total;
            fileCount = count;
            Interlocked.Exchange(ref doneBytes, 0);
            Interlocked.Exchange(ref fileNumber, 0);
            currentFile = "";
            samples.Clear();
            watch.Restart();
            progressActive = true;
            progress.Value = 0;
            btnOpen.Visible = false;
            SetThreadExecutionState(EsContinuous | EsSystemRequired); // don't let the PC sleep mid-copy
            Tick();
        }

        void EndProgress(string summary, bool complete)
        {
            progressActive = false;
            SetThreadExecutionState(EsContinuous);
            lblTransfer.Text = summary;
            double secs = watch.Elapsed.TotalSeconds;
            long done = Interlocked.Read(ref doneBytes);
            lblStats.Text = done > 0 && secs > 0 ? Util.Bytes(done) + " in " + Util.Duration(secs) + " (" + Util.Bytes((long)(done / secs)) + "/s)" : "";
            if (complete) progress.Value = progress.Maximum;
        }

        void Tick()
        {
            if (!progressActive) return;
            double t = watch.Elapsed.TotalSeconds;
            long done = Interlocked.Read(ref doneBytes), total = totalBytes;
            samples.Enqueue(new KeyValuePair<double, long>(t, done));
            while (samples.Count > 2 && t - samples.Peek().Key > 5) samples.Dequeue();
            var first = samples.Peek();
            double dt = t - first.Key;
            double rate = dt > 0.5 ? (done - first.Value) / dt : 0;
            progress.Value = total > 0 ? (int)Math.Min(1000, done * 1000 / total) : 0;
            string stats = Util.Bytes(done) + " of " + Util.Bytes(total);
            if (rate > 0)
            {
                stats += "  ·  " + Util.Bytes((long)rate) + "/s";
                if (total > done) stats += "  ·  about " + Util.Duration((total - done) / rate) + " left";
            }
            lblStats.Text = stats;
            int n = Thread.VolatileRead(ref fileNumber);
            lblTransfer.Text = n == 0 ? progressVerb + "…" : progressVerb + " " + n.ToString("N0") + " of " + fileCount.ToString("N0") + ":  " + currentFile;
        }

        // ---------- connecting ----------

        static string NewCode()
        {
            var b = new byte[4];
            using (var r = new RNGCryptoServiceProvider()) r.GetBytes(b);
            return (BitConverter.ToUInt32(b, 0) % 1000000).ToString("D6");
        }

        const string Magic = "LANDROP2";
        const byte AuthCode = 1, AuthKey = 2;

        void ShowMe(string publicAddr)
        {
            var addrs = Util.LocalAddresses();
            lblMe.Text = "This PC: " + Environment.MachineName
                + "    On this network: " + (addrs.Count > 0 ? string.Join(", ", addrs) : "unknown")
                + (publicAddr != null ? "    Internet: " + publicAddr : "");
        }

        void StartHosting(string code)
        {
            X509Certificate2 cert;
            try { cert = Util.MakeCert(); }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Couldn't set up encryption:\n" + ex.Message, "LAN Drop", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            TcpListener l;
            try
            {
                l = new TcpListener(opt.Loopback ? IPAddress.Loopback : IPAddress.Any, opt.Port);
                l.Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show(this, "Couldn't start waiting for a connection on port " + opt.Port + ":\n" + ex.Message, "LAN Drop", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            listener = l;
            pairCode = code ?? NewCode();
            byte[] secret = Util.RandomBytes(16);
            lblCode.Text = "Code:  " + pairCode.Substring(0, 3) + " " + pairCode.Substring(3) + "   (same network only)";
            txtInvite.Text = "Getting this PC's internet address…";
            btnCopy.Enabled = false;
            lblStatus.Text = "Waiting for the other PC to connect…";
            UpdateUi();
            Log("Waiting for a connection on port " + opt.Port + ".");
            new Thread(() => AcceptLoop(l, cert, secret)) { IsBackground = true, Name = "accept" }.Start();

            int port = opt.Port;
            new Thread(() =>
            {
                var inv = new Invite { Port = port, Fingerprint = Util.Sha256(cert.RawData), Secret = secret };
                string pub = null;
                if (opt.Loopback) inv.Addresses.Add(IPAddress.Loopback);
                else
                {
                    pub = Util.PublicAddress();
                    if (pub != null) inv.Addresses.Add(IPAddress.Parse(pub));
                    foreach (var a in Util.LocalAddresses().Take(4)) inv.Addresses.Add(IPAddress.Parse(a));
                }
                string key = inv.Encode();
                if (opt.InviteFile != null) try { File.WriteAllText(opt.InviteFile, key); } catch { }
                UI(() =>
                {
                    ShowMe(pub);
                    if (listener != l) return;
                    txtInvite.Text = key;
                    btnCopy.Enabled = true;
                    if (pub == null && !opt.Loopback)
                        Log("Couldn't find this PC's internet address, so this invite key only works on this network.");
                });
            }) { IsBackground = true, Name = "invite" }.Start();
        }

        void StopHosting()
        {
            var l = listener;
            listener = null;
            if (l != null) try { l.Stop(); } catch { }
            if (IsDisposed) return;
            lblCode.Text = "";
            txtInvite.Text = "";
            btnCopy.Enabled = false;
            if (conn == null) lblStatus.Text = "Not connected";
            UpdateUi();
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
                    var ip = ((IPEndPoint)c.Client.RemoteEndPoint).Address;
                    bool local = !opt.PublicOnly && Util.IsLocal(ip);
                    Connection.Prepare(c);
                    ssl = new SslStream(c.GetStream(), false);
                    ssl.AuthenticateAsServer(cert, false, SslProtocols.Tls12, false);
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
                            why = "From outside " + Environment.MachineName + "'s network, connect with the invite key instead of the code.";
                        else if (code != pairCode)
                        {
                            why = "That code is wrong. Check the code shown on " + Environment.MachineName + ".";
                            if (++wrong >= 5)
                            {
                                wrong = 0;
                                string nc = NewCode();
                                pairCode = nc;
                                UI(() => { lblCode.Text = "Code:  " + nc.Substring(0, 3) + " " + nc.Substring(3) + "   (same network only)"; });
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
                    cn.Send(w => { w.Write(true); w.Write(Environment.MachineName); });
                    cn.ReceiveTimeout = 0;
                    cn.PeerName = name;
                }
                catch
                {
                    if (cn != null) cn.Dispose();
                    else
                    {
                        if (ssl != null) try { ssl.Dispose(); } catch { }
                        c.Close();
                    }
                    continue;
                }
                var accepted = cn;
                UI(() =>
                {
                    if (listener != l) { accepted.Dispose(); return; } // user stopped waiting meanwhile
                    StopHosting();
                    OnConnected(accepted);
                });
                return;
            }
        }

        void StartConnect()
        {
            if (connecting || conn != null || listener != null) return;
            string addr = txtAddress.Text.Trim(), code = txtCode.Text.Replace(" ", "").Trim();
            Invite inv = null;
            if (Invite.LooksLikeKey(addr))
            {
                inv = Invite.TryParse(addr);
                if (inv == null)
                {
                    MessageBox.Show(this, "That invite key is incomplete or damaged. Copy the whole key again (it starts with LD1-).", "LAN Drop", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }
            }
            else if (addr == "" || code == "")
            {
                MessageBox.Show(this, "On the same network: enter the other PC's address and the code it shows.\nOver the internet: paste the invite key it shows into the first box.", "LAN Drop", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            string target = inv != null ? "the PC in the invite key" : addr;
            connecting = true;
            lblStatus.Text = "Connecting to " + target + "…";
            UpdateUi();
            int port = opt.Port;
            const string hint = "\n\nCheck that LAN Drop on the other PC is still waiting for a connection.";
            new Thread(() =>
            {
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
                        var ar = c.BeginConnect(addr, port, null, null);
                        if (!ar.AsyncWaitHandle.WaitOne(8000))
                            throw new Exception("No answer from " + addr + "." + hint + " Also check the address.");
                        c.EndConnect(ar);
                    }
                    Connection.Prepare(c);
                    // With an invite key, only the exact PC that made the key is accepted.
                    var ssl = new SslStream(c.GetStream(), false, (s, cert, chain, errors) =>
                        inv == null || (cert != null && Util.SameBytes(Util.Sha256(cert.GetRawCertData()), inv.Fingerprint)));
                    try { ssl.AuthenticateAsClient("LAN Drop", null, SslProtocols.Tls12, false); }
                    catch (AuthenticationException)
                    {
                        throw new Exception("The PC that answered isn't the one that made this invite key. The key may be from an earlier session: ask for a new one.");
                    }
                    cn = new Connection(c, ssl);
                    cn.Send(w =>
                    {
                        w.Write(Magic);
                        if (inv != null) { w.Write(AuthKey); w.Write(inv.Secret); }
                        else { w.Write(AuthCode); w.Write(code); }
                        w.Write(Environment.MachineName);
                    });
                    bool ok = cn.Reader.ReadBoolean();
                    string info = cn.Reader.ReadString();
                    if (!ok) throw new Exception(info);
                    cn.ReceiveTimeout = 0;
                    cn.PeerName = info;
                    var done = cn;
                    UI(() => { connecting = false; OnConnected(done); });
                }
                catch (Exception ex)
                {
                    if (cn != null) cn.Dispose(); else if (c != null) c.Close();
                    string m = ex is SocketException || ex is IOException
                        ? "Couldn't connect to " + target + ":\n" + ex.Message + hint
                        : ex.Message;
                    Log("Couldn't connect to " + target + ": " + ex.Message.Split('\n')[0]);
                    UI(() =>
                    {
                        connecting = false;
                        lblStatus.Text = "Not connected";
                        UpdateUi();
                        if (!opt.ExitWhenDone) MessageBox.Show(this, m, "LAN Drop", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        else TestExit(false);
                    });
                }
            }) { IsBackground = true, Name = "connect" }.Start();
        }

        void OnConnected(Connection cn)
        {
            conn = cn;
            userDisconnect = false;
            lblStatus.Text = "Connected to " + cn.PeerName + " (" + cn.PeerAddress + ")";
            Log("Connected to " + cn.PeerName + " at " + cn.PeerAddress + ".");
            UpdateUi();
            new Thread(() => ReadLoop(cn)) { IsBackground = true, Name = "read" }.Start();
            if (opt.Send != null) StartOffer(new[] { opt.Send });
        }

        void Disconnect()
        {
            if (Busy && MessageBox.Show(this, "A transfer is in progress. Disconnect anyway?", "LAN Drop", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;
            userDisconnect = true;
            var c = conn;
            if (c != null) c.Dispose(); // the reader notices and cleans up
        }

        void OnDisconnected(Connection cn, string why)
        {
            if (conn != cn || closingForTest) return;
            conn = null;
            cn.Dispose();
            sendCancel = true;
            int m = mode;
            outgoing = null;
            mode = ModeNone;
            if (progressActive)
                EndProgress(m == ModeReceiving
                    ? "Stopped: the connection was lost. Finished files are saved. Send again and they'll be skipped."
                    : "Stopped: the connection was lost. Send again to pick up where it stopped.", false);
            else if (m == ModeOffering) lblTransfer.Text = "";
            Interlocked.Exchange(ref busyFlag, 0);
            lblStatus.Text = "Not connected";
            Log(userDisconnect ? "Disconnected." : "Disconnected: " + why);
            UpdateUi();
            if (opt.ExitWhenDone) TestExit(false);
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
                            if (mode == ModeSending) { sendCancel = true; Log(cn.PeerName + " cancelled the transfer."); }
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
            UI(() => OnDisconnected(cn, why));
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

        void StartOffer(string[] paths)
        {
            var cn = conn;
            if (cn == null) return;
            if (!TryBegin())
            {
                MessageBox.Show(this, "Wait for the current transfer to finish first.", "LAN Drop", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            mode = ModeListing;
            btnOpen.Visible = false;
            progress.Value = 0;
            lblStats.Text = "";
            lblTransfer.Text = "Getting the list of files…";
            UpdateUi();
            new Thread(() =>
            {
                var items = new List<OfferItem>();
                var problems = new List<string>();
                foreach (var p in paths) Util.AddPath(p, items, problems);
                Util.Dedupe(items);
                foreach (var pr in problems) Log("Left out " + pr);
                if (items.Count == 0)
                {
                    mode = ModeNone;
                    UI(() => { lblTransfer.Text = "Nothing to send: no files found there."; });
                    EndBusy();
                    return;
                }
                var o = new Offer { Id = Interlocked.Increment(ref offerCounter), Items = items, Total = items.Sum(x => x.Size) };
                outgoing = o;
                sendCancel = false;
                mode = ModeOffering;
                string what = Util.Count(items.Count, "file", "files") + " (" + Util.Bytes(o.Total) + ")";
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
                    mode = ModeNone;
                    Log("Couldn't send the offer: " + ex.Message);
                    UI(() => { lblTransfer.Text = ""; });
                    EndBusy();
                    return;
                }
                Log("Offered " + what + " to " + cn.PeerName + ".");
                UI(() => { lblTransfer.Text = "Waiting for " + cn.PeerName + " to accept " + what + "…"; UpdateUi(); });
            }) { IsBackground = true, Name = "list" }.Start();
        }

        void HandleAccept(Connection cn, int id, HashSet<int> skip)
        {
            var o = outgoing;
            if (o == null || o.Id != id || mode != ModeOffering)
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
            mode = ModeSending;
            UISync(() => { BeginProgress("Sending", total, count); UpdateUi(); });
            int skipped = o.Items.Count - count;
            Log(cn.PeerName + " accepted." + (skipped > 0 ? " " + Util.Count(skipped, "file is", "files are") + " already there and will be skipped." : ""));
            new Thread(() => SendFiles(cn, o, skip)) { IsBackground = true, Name = "send" }.Start();
        }

        void HandleDecline(int id, string reason)
        {
            var o = outgoing;
            if (o == null || o.Id != id) return;
            outgoing = null;
            mode = ModeNone;
            Log(Peer + " didn't take the files: " + reason);
            UI(() => { lblTransfer.Text = Peer + " didn't take the files: " + reason; });
            EndBusy();
            TestExit(false);
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
                    using (HashAlgorithm sha = new SHA256Cng())
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
                                    sha.TransformBlock(buf, 0, n, null, 0);
                                    int len = n;
                                    cn.Send(w => { w.Write(Msg.Chunk); w.Write(len); w.Write(buf, 0, len); });
                                    sent += n;
                                    Interlocked.Add(ref doneBytes, n);
                                }
                            }
                        }
                        if (err == null)
                        {
                            sha.TransformFinalBlock(new byte[0], 0, 0);
                            byte[] h = sha.Hash;
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
                if (cancelled) UI(() => { lblTransfer.Text = "Cancelling…"; });
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
            mode = ModeNone;
            string peer = Peer;
            string summary = cancelled
                ? "Cancelled. " + Util.Count(ok, "file", "files") + " had already arrived on " + peer + "."
                : "Done. " + Util.Count(ok, "file", "files") + " sent and checked on " + peer
                  + (skipped > 0 ? ", " + skipped.ToString("N0") + " already there" : "")
                  + (failedTotal > 0 ? ". " + failedTotal.ToString("N0") + " failed" : "") + ".";
            Log(summary);
            foreach (var f in failed) Log("Failed: " + f);
            UI(() =>
            {
                EndProgress(summary, !cancelled && failedTotal == 0);
                if (failedTotal > 0) ShowFailures(peer + " couldn't save " + Util.Count(failedTotal, "file", "files") + ":", failed, failedTotal);
            });
            EndBusy();
            TestExit(!cancelled && failedTotal == 0);
        }

        void ShowFailures(string title, List<string> failed, int total)
        {
            if (opt.ExitWhenDone) return;
            var sb = new StringBuilder(title + "\n\n");
            foreach (var f in failed.Take(15)) sb.AppendLine(f);
            if (total > 15) sb.AppendLine("…and " + (total - 15).ToString("N0") + " more (see the log).");
            sb.AppendLine("\nSending the same files again will retry just these.");
            MessageBox.Show(this, sb.ToString(), "LAN Drop", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        void CancelTransfer()
        {
            int m = mode;
            if (m == ModeOffering)
            {
                outgoing = null;
                mode = ModeNone;
                lblTransfer.Text = "You withdrew the offer.";
                Log("You withdrew the offer.");
                EndBusy();
            }
            else if (m == ModeSending)
            {
                sendCancel = true;
                btnCancel.Enabled = false;
                lblTransfer.Text = "Cancelling…";
            }
            else if (m == ModeReceiving)
            {
                rxCancelled = true;
                btnCancel.Enabled = false;
                var c = conn;
                if (c != null) try { c.Send(w => w.Write(Msg.Cancel)); } catch { }
                Log("You cancelled the transfer.");
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
            mode = ModeChoosing;
            UI(UpdateUi);
            Log(cn.PeerName + " wants to send " + Util.Count(offer.Items.Count, "file", "files") + " (" + Util.Bytes(offer.Total) + ").");
            string folder = null;
            bool skipExisting = true;
            if (opt.AcceptTo != null) folder = Path.GetFullPath(opt.AcceptTo);
            else
            {
                UISync(() =>
                {
                    if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
                    Activate();
                    using (var d = new AcceptDialog(cn.PeerName, offer))
                    {
                        if (d.ShowDialog(this) == DialogResult.OK) { folder = d.Folder; skipExisting = d.SkipExisting; }
                    }
                });
            }
            if (conn != cn) return; // disconnected while the dialog was open
            if (folder == null)
            {
                mode = ModeNone;
                cn.Send(w => { w.Write(Msg.Decline); w.Write(offer.Id); w.Write("they declined."); });
                Log("You declined the files.");
                EndBusy();
                return;
            }

            var skip = new List<int>();
            long total = 0;
            int count = 0;
            for (int i = 0; i < offer.Items.Count; i++)
            {
                var it = offer.Items[i];
                bool already = false;
                if (skipExisting)
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
            mode = ModeReceiving;
            UISync(() => { BeginProgress("Receiving", total, count); UpdateUi(); });
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
                rxHash = new SHA256Cng();
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
                rxHash.TransformBlock(recvBuf, 0, len, null, 0);
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
                rxHash.TransformFinalBlock(new byte[0], 0, 0);
                bool ok = rxWritten == it.Size && hash.Length == 32 && rxHash.Hash.SequenceEqual(hash);
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
                rxFailed.Add(rxOffer.Items[rxIndex].RelPath + ": on the sending PC, " + reason);
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
            mode = ModeNone;
            string summary = wasCancelled
                ? "Cancelled. " + Util.Count(ok, "file", "files") + " had finished and are saved."
                : "Done. " + Util.Count(ok, "file", "files") + " received and checked"
                  + (skipped > 0 ? ", " + skipped.ToString("N0") + " already there" : "")
                  + (failed.Count > 0 ? ". " + failed.Count.ToString("N0") + " failed" : "") + ".";
            Log(summary + " Saved in " + root);
            foreach (var f in failed) Log("Failed: " + f);
            UI(() =>
            {
                EndProgress(summary, !wasCancelled && failed.Count == 0);
                lastReceivedFolder = root;
                btnOpen.Visible = true;
                if (failed.Count > 0) ShowFailures("These files couldn't be saved:", failed, failed.Count);
            });
            EndBusy();
            TestExit(!wasCancelled && failed.Count == 0);
        }
    }

    class AcceptDialog : Form
    {
        public string Folder;
        public bool SkipExisting;
        readonly TextBox txtFolder;
        readonly Label lblSpace;
        readonly CheckBox chkSkip;
        readonly long total;

        public AcceptDialog(string peer, Offer offer)
        {
            SuspendLayout();
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            Font = new Font("Segoe UI", 9F);
            Text = "Incoming files";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = MinimizeBox = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterParent;
            TopMost = true;
            ClientSize = new Size(560, 470);
            total = offer.Total;

            Add(new Label { Text = peer + " wants to send you " + Util.Count(offer.Items.Count, "file", "files") + " (" + Util.Bytes(offer.Total) + ").", Font = new Font("Segoe UI", 10F, FontStyle.Bold) }, 12, 12, 536, 24);
            var list = Add(new ListView { View = View.Details, FullRowSelect = true, HeaderStyle = ColumnHeaderStyle.Nonclickable }, 12, 42, 536, 230);
            list.Columns.Add("File", 410);
            list.Columns.Add("Size", 100, HorizontalAlignment.Right);
            list.BeginUpdate();
            foreach (var it in offer.Items.Take(2000))
                list.Items.Add(new ListViewItem(new[] { it.RelPath.Replace('/', '\\'), Util.Bytes(it.Size) }));
            if (offer.Items.Count > 2000)
                list.Items.Add(new ListViewItem(new[] { "…and " + (offer.Items.Count - 2000).ToString("N0") + " more", "" }));
            list.EndUpdate();

            Add(new Label { Text = "Save in this folder:" }, 12, 284, 300, 20);
            txtFolder = Add(new TextBox { Text = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads") }, 12, 306, 438, 24);
            var browse = Add(new Button { Text = "Browse…" }, 456, 304, 92, 28);
            lblSpace = Add(new Label(), 12, 336, 536, 20);
            chkSkip = Add(new CheckBox { Text = "Skip files that are already there (same size and date), to finish an earlier copy", Checked = true }, 12, 362, 536, 24);
            Add(new Label { Text = "Folders keep their names, so a sent folder arrives as a folder inside this one.", ForeColor = SystemColors.GrayText }, 12, 390, 536, 20);
            var accept = Add(new Button { Text = "Accept" }, 336, 426, 104, 32);
            var decline = Add(new Button { Text = "Decline", DialogResult = DialogResult.Cancel }, 444, 426, 104, 32);
            CancelButton = decline;

            browse.Click += delegate
            {
                using (var d = new FolderBrowserDialog { Description = "Where should the files go?", SelectedPath = txtFolder.Text })
                    if (d.ShowDialog(this) == DialogResult.OK) txtFolder.Text = d.SelectedPath;
            };
            txtFolder.TextChanged += delegate { UpdateSpace(); };
            accept.Click += delegate
            {
                try
                {
                    string f = Path.GetFullPath(txtFolder.Text.Trim());
                    Directory.CreateDirectory(f);
                    Folder = f;
                    SkipExisting = chkSkip.Checked;
                    DialogResult = DialogResult.OK;
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, "Can't use that folder: " + ex.Message, "LAN Drop", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            };
            ResumeLayout(false);
            UpdateSpace();
        }

        T Add<T>(T c, int x, int y, int w, int h) where T : Control
        {
            c.SetBounds(x, y, w, h);
            Controls.Add(c);
            return c;
        }

        void UpdateSpace()
        {
            try
            {
                var d = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(txtFolder.Text.Trim())));
                long free = d.AvailableFreeSpace;
                bool enough = free > total;
                lblSpace.Text = "Free space on drive " + d.Name.TrimEnd('\\') + "  " + Util.Bytes(free) + (enough ? "" : ". That's not enough for all " + Util.Bytes(total) + ".");
                lblSpace.ForeColor = enough ? SystemColors.ControlText : Color.Firebrick;
            }
            catch
            {
                lblSpace.Text = "";
            }
        }
    }
}
