using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using LanDrop.Core;

namespace LanDrop.App;

sealed class MainWindow : Window, IPeerHost
{
    readonly AppOptions opt;
    readonly Peer peer;

    TextBlock meText, codeText, codeNote, statusText, dropText, transferText, statsText;
    Button hostBtn, copyBtn, connectBtn, disconnectBtn, addFilesBtn, addFolderBtn, cancelBtn, openBtn;
    TextBox inviteBox, addressBox, codeBox, logBox;
    Border dropZone;
    ProgressBar progress;

    readonly DispatcherTimer timer;
    readonly Stopwatch watch = new();
    readonly Queue<(double T, long Bytes)> samples = new();
    bool transferRunning, closeConfirmed;
    string verb, lastFolder, publicAddress;

    static readonly IBrush DropOn = new SolidColorBrush(Color.FromArgb(0x26, 0x3B, 0x82, 0xF6));
    static readonly IBrush DropOff = new SolidColorBrush(Color.FromArgb(0x10, 0x80, 0x80, 0x80));
    static readonly IBrush DropEdgeOn = new SolidColorBrush(Color.FromArgb(0x99, 0x3B, 0x82, 0xF6));
    static readonly IBrush DropEdgeOff = new SolidColorBrush(Color.FromArgb(0x40, 0x80, 0x80, 0x80));
    static readonly IBrush PanelEdge = new SolidColorBrush(Color.FromArgb(0x40, 0x80, 0x80, 0x80));

    public MainWindow(AppOptions options)
    {
        opt = options;
        peer = new Peer(this, new PeerOptions { Port = opt.Port ?? Peer.DefaultPort, Loopback = opt.Loopback });
        Title = "LAN Drop";
        Width = 680;
        Height = 780;
        MinWidth = 560;
        MinHeight = 660;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;
        try { Icon = MakeIcon(); } catch { }
        Content = Build();
        timer = new DispatcherTimer(TimeSpan.FromMilliseconds(250), DispatcherPriority.Background, (_, _) => Tick());
        timer.Start();
        Opened += (_, _) => OnOpened();
        Closing += OnClosing;
        UpdateMe();
        Refresh();
    }

    // ---------- layout ----------

    Control Build()
    {
        meText = new TextBlock { TextWrapping = TextWrapping.Wrap, Opacity = 0.75, FontSize = 12 };
        hostBtn = new Button { Content = "Wait for connection", MinWidth = 180, HorizontalContentAlignment = HorizontalAlignment.Center };
        codeText = new TextBlock { FontSize = 22, FontWeight = FontWeight.Bold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(16, 0, 0, 0) };
        codeNote = new TextBlock { Text = "same network only", Opacity = 0.65, FontSize = 12, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(10, 4, 0, 0) };
        inviteBox = new TextBox { IsReadOnly = true, Watermark = "Click Wait for connection to get a key", FontSize = 12 };
        copyBtn = new Button { Content = "Copy key", MinWidth = 110, HorizontalContentAlignment = HorizontalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
        addressBox = new TextBox { Watermark = "Address, or paste an invite key" };
        codeBox = new TextBox { Watermark = "Code", Width = 100, MaxLength = 12, Margin = new Thickness(8, 0, 0, 0) };
        connectBtn = new Button { Content = "Connect", MinWidth = 110, HorizontalContentAlignment = HorizontalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
        statusText = new TextBlock { VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };
        disconnectBtn = new Button { Content = "Disconnect", MinWidth = 110, HorizontalContentAlignment = HorizontalAlignment.Center };

        var connection = new Border
        {
            BorderBrush = PanelEdge,
            BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8),
            Padding = new Thickness(16, 12),
            Child = new StackPanel
            {
                Spacing = 10,
                Children =
                {
                    new TextBlock { Text = "Connection", FontWeight = FontWeight.SemiBold },
                    meText,
                    Cols("Auto,Auto,*", hostBtn, codeText, codeNote),
                    Cols("90,*,Auto", Label("Invite key"), inviteBox, copyBtn),
                    Cols("90,*,Auto,Auto", Label("Connect to"), addressBox, codeBox, connectBtn),
                    new TextBlock { Text = "Same network: the other computer's address and code.   Over the internet: paste its invite key.", Opacity = 0.65, FontSize = 12, TextWrapping = TextWrapping.Wrap },
                    Cols("*,Auto", statusText, disconnectBtn),
                },
            },
        };

        dropText = new TextBlock { TextAlignment = TextAlignment.Center, FontSize = 15, TextWrapping = TextWrapping.Wrap, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(16) };
        dropZone = new Border { Height = 130, CornerRadius = new CornerRadius(10), BorderThickness = new Thickness(2), Child = dropText };
        DragDrop.SetAllowDrop(dropZone, true);
        dropZone.AddHandler(DragDrop.DragOverEvent, OnDragOver);
        dropZone.AddHandler(DragDrop.DropEvent, OnDrop);

        addFilesBtn = new Button { Content = "Add files…", MinWidth = 120, HorizontalContentAlignment = HorizontalAlignment.Center };
        addFolderBtn = new Button { Content = "Add folder…", MinWidth = 120, HorizontalContentAlignment = HorizontalAlignment.Center };

        transferText = new TextBlock { TextTrimming = TextTrimming.CharacterEllipsis };
        progress = new ProgressBar { Minimum = 0, Maximum = 1000, Height = 8, MinHeight = 8 };
        statsText = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Opacity = 0.8, FontSize = 12, TextTrimming = TextTrimming.CharacterEllipsis };
        openBtn = new Button { Content = "Open folder", IsVisible = false, MinWidth = 110, HorizontalContentAlignment = HorizontalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
        cancelBtn = new Button { Content = "Cancel", MinWidth = 110, HorizontalContentAlignment = HorizontalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };

        logBox = new TextBox { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, FontSize = 12, VerticalContentAlignment = VerticalAlignment.Top };

        var top = new StackPanel
        {
            Spacing = 12,
            Children =
            {
                connection,
                dropZone,
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Children = { addFilesBtn, addFolderBtn } },
                new StackPanel { Spacing = 6, Margin = new Thickness(0, 6, 0, 0), Children = { transferText, progress, Cols("*,Auto,Auto", statsText, openBtn, cancelBtn) } },
            },
        };
        var root = new DockPanel { Margin = new Thickness(16) };
        DockPanel.SetDock(top, Dock.Top);
        logBox.Margin = new Thickness(0, 12, 0, 0);
        root.Children.Add(top);
        root.Children.Add(logBox);

        hostBtn.Click += async (_, _) =>
        {
            if (peer.IsHosting) { peer.StopHosting(); return; }
            string err = peer.StartHosting();
            if (err != null) await Dialogs.Message(this, "LAN Drop", err);
        };
        copyBtn.Click += async (_, _) =>
        {
            string key = peer.InviteKey;
            if (key == null || Clipboard == null) return;
            await Clipboard.SetTextAsync(key);
            Log("Invite key copied. Send it to the other person (Discord, text, email).");
        };
        connectBtn.Click += (_, _) => DoConnect();
        addressBox.KeyDown += (_, e) => { if (e.Key == Key.Enter) DoConnect(); };
        codeBox.KeyDown += (_, e) => { if (e.Key == Key.Enter) DoConnect(); };
        addressBox.TextChanged += (_, _) => Refresh();
        disconnectBtn.Click += async (_, _) =>
        {
            if (peer.IsBusy && !await Dialogs.Confirm(this, "Disconnect?", "A transfer is in progress. Disconnect anyway?", "Disconnect", "Keep going")) return;
            peer.Disconnect();
        };
        cancelBtn.Click += (_, _) => { peer.Cancel(); cancelBtn.IsEnabled = false; };
        openBtn.Click += async (_, _) =>
        {
            if (lastFolder == null) return;
            try { await Launcher.LaunchDirectoryInfoAsync(new DirectoryInfo(lastFolder)); }
            catch { try { Process.Start(new ProcessStartInfo(lastFolder) { UseShellExecute = true }); } catch { } }
        };
        addFilesBtn.Click += async (_, _) =>
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Choose files to send", AllowMultiple = true });
            Send(files.Select(f => f.TryGetLocalPath()));
        };
        addFolderBtn.Click += async (_, _) =>
        {
            var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "Choose a folder to send (it's sent with everything in it)", AllowMultiple = true });
            Send(folders.Select(f => f.TryGetLocalPath()));
        };
        return root;
    }

    static TextBlock Label(string text) => new() { Text = text, VerticalAlignment = VerticalAlignment.Center };

    static Grid Cols(string columns, params Control[] children)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions(columns) };
        for (int i = 0; i < children.Length; i++)
        {
            Grid.SetColumn(children[i], i);
            g.Children.Add(children[i]);
        }
        return g;
    }

    static WindowIcon MakeIcon()
    {
        using var bmp = IconArt.Render(128);
        var ms = new MemoryStream();
        bmp.Save(ms);
        ms.Position = 0;
        return new WindowIcon(ms);
    }

    // ---------- state ----------

    void UpdateMe()
    {
        var addrs = Util.LocalAddresses();
        meText.Text = "This computer: " + peer.MachineName
            + "     On this network: " + (addrs.Count > 0 ? string.Join(", ", addrs) : "unknown")
            + (publicAddress != null ? "     Internet: " + publicAddress : "");
    }

    void Refresh()
    {
        bool connected = peer.IsConnected, hosting = peer.IsHosting, connecting = peer.IsConnecting;
        hostBtn.IsEnabled = !connected && !connecting;
        hostBtn.Content = hosting ? "Stop waiting" : "Wait for connection";
        string code = hosting ? peer.PairCode : null;
        codeText.Text = code is { Length: 6 } ? "Code: " + code[..3] + " " + code[3..] : "";
        codeNote.IsVisible = code != null;
        string key = hosting ? peer.InviteKey : null;
        inviteBox.Text = !hosting ? "" : key ?? "Getting this computer's internet address…";
        copyBtn.IsEnabled = key != null;
        addressBox.IsEnabled = connectBtn.IsEnabled = !connected && !hosting && !connecting;
        codeBox.IsEnabled = addressBox.IsEnabled && !Invite.LooksLikeKey(addressBox.Text);
        disconnectBtn.IsEnabled = connected;
        statusText.Text = connected ? "Connected to " + peer.PeerName + " (" + peer.PeerAddress + ")"
            : connecting ? "Connecting…"
            : hosting ? "Waiting for the other computer to connect…"
            : "Not connected";
        bool canSend = connected && !peer.IsBusy;
        addFilesBtn.IsEnabled = addFolderBtn.IsEnabled = canSend;
        dropZone.Background = canSend ? DropOn : DropOff;
        dropZone.BorderBrush = canSend ? DropEdgeOn : DropEdgeOff;
        dropText.Opacity = canSend ? 1 : 0.6;
        dropText.Text = !connected ? "Connect to the other computer first.\nThen drop files or folders here to send them."
            : peer.IsBusy ? "A transfer is in progress."
            : "Drop files or folders here to send them to " + peer.PeerName + ".";
        var act = peer.CurrentActivity;
        cancelBtn.IsEnabled = act is Peer.Activity.Offering or Peer.Activity.Sending or Peer.Activity.Receiving;
        if (act == Peer.Activity.Listing) transferText.Text = "Getting the list of files…";
        else if (act == Peer.Activity.Offering) transferText.Text = "Waiting for " + peer.PeerName + " to accept " + peer.OfferSummary + "…";
        else if (act == Peer.Activity.Choosing) transferText.Text = peer.PeerName + " wants to send you files.";
        Title = connected ? "LAN Drop - connected to " + peer.PeerName : "LAN Drop";
    }

    void Tick()
    {
        if (!transferRunning) return;
        double t = watch.Elapsed.TotalSeconds;
        long done = peer.DoneBytes, total = peer.TotalBytes;
        samples.Enqueue((t, done));
        while (samples.Count > 2 && t - samples.Peek().T > 5) samples.Dequeue();
        var first = samples.Peek();
        double dt = t - first.T;
        double rate = dt > 0.5 ? (done - first.Bytes) / dt : 0;
        progress.Value = total > 0 ? Math.Min(1000, done * 1000.0 / total) : 0;
        string stats = Util.Bytes(done) + " of " + Util.Bytes(total);
        if (rate > 0)
        {
            stats += "  ·  " + Util.Bytes((long)rate) + "/s";
            if (total > done) stats += "  ·  about " + Util.Duration((total - done) / rate) + " left";
        }
        statsText.Text = stats;
        int n = peer.FileNumber;
        transferText.Text = n == 0 ? verb + "…" : verb + " " + n.ToString("N0") + " of " + peer.FileCount.ToString("N0") + ":  " + peer.CurrentFile;
    }

    // ---------- actions ----------

    async void DoConnect()
    {
        if (!connectBtn.IsEnabled) return;
        string err = peer.Connect(addressBox.Text, codeBox.Text);
        if (err != null) await Dialogs.Message(this, "LAN Drop", err);
    }

    async void Send(IEnumerable<string> paths)
    {
        var list = paths.Where(p => !string.IsNullOrEmpty(p)).ToList();
        if (list.Count == 0) return;
        openBtn.IsVisible = false;
        progress.Value = 0;
        statsText.Text = "";
        string err = peer.Offer(list);
        if (err != null) await Dialogs.Message(this, "LAN Drop", err);
    }

    void OnDragOver(object sender, DragEventArgs e)
    {
        e.DragEffects = peer.IsConnected && !peer.IsBusy && e.DataTransfer.Contains(DataFormat.File) ? DragDropEffects.Copy : DragDropEffects.None;
    }

    void OnDrop(object sender, DragEventArgs e)
    {
        var items = e.DataTransfer.TryGetFiles();
        if (items != null) Send(items.Select(i => i.TryGetLocalPath()));
    }

    void OnOpened()
    {
        if (opt.InviteFile != null) peer.StartHosting();
        if (!opt.Smoke) return;
        // Automated check: start waiting, take a picture once the key is ready, then quit.
        string err = peer.StartHosting("482913");
        if (err != null) { Console.Error.WriteLine(err); Program.Quit(2); return; }
        DispatcherTimer.RunOnce(() => { Console.Error.WriteLine("Timed out."); Program.Quit(3); }, TimeSpan.FromSeconds(30));
    }

    async void OnClosing(object sender, WindowClosingEventArgs e)
    {
        if (closeConfirmed || !peer.IsBusy)
        {
            timer.Stop();
            peer.Dispose();
            return;
        }
        e.Cancel = true;
        if (await Dialogs.Confirm(this, "Quit LAN Drop?", "A transfer is in progress. Quit anyway?", "Quit", "Keep going"))
        {
            closeConfirmed = true;
            Close();
        }
    }

    void SaveScreenshot(string path)
    {
        double scale = RenderScaling;
        var size = new PixelSize((int)(Bounds.Width * scale), (int)(Bounds.Height * scale));
        using var bmp = new RenderTargetBitmap(size, new Vector(96 * scale, 96 * scale));
        bmp.Render(this);
        bmp.Save(path);
    }

    // ---------- IPeerHost (called from background threads) ----------

    static void Post(Action a) => Dispatcher.UIThread.Post(a);

    public void Log(string message) => Post(() =>
    {
        string line = DateTime.Now.ToString("HH:mm:ss") + "  " + message;
        logBox.Text = string.IsNullOrEmpty(logBox.Text) ? line : logBox.Text + Environment.NewLine + line;
        logBox.CaretIndex = logBox.Text.Length;
    });

    public void StateChanged() => Post(Refresh);

    public void CodeChanged(string code) => Post(Refresh);

    public void InviteReady(string key, string pub) => Post(() =>
    {
        publicAddress = pub;
        UpdateMe();
        Refresh();
        if (opt.InviteFile != null) try { File.WriteAllText(opt.InviteFile, key); } catch { }
        if (opt.Smoke)
        {
            DispatcherTimer.RunOnce(() =>
            {
                try { if (opt.Screenshot != null) SaveScreenshot(opt.Screenshot); }
                catch (Exception ex) { Console.Error.WriteLine("Screenshot failed: " + ex.Message); Program.Quit(4); return; }
                Console.WriteLine("Smoke test passed: the window opened and is waiting with key " + key[..12] + "…");
                Program.Quit(0);
            }, TimeSpan.FromSeconds(1));
        }
    });

    public void ConnectFailed(string message) => Post(async () => await Dialogs.Message(this, "Couldn't connect", message));

    public AcceptChoice ChooseIncoming(string peerName, Offer offer) =>
        Dispatcher.UIThread.InvokeAsync(async () =>
        {
            if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
            Activate();
            return await new AcceptDialog(peerName, offer).ShowDialog<AcceptChoice>(this);
        }).GetAwaiter().GetResult();

    public void TransferStarted(string v, long totalBytes, int fileCount) => Post(() =>
    {
        verb = v;
        transferRunning = true;
        samples.Clear();
        watch.Restart();
        progress.Value = 0;
        openBtn.IsVisible = false;
        Tick();
    });

    public void TransferEnded(TransferResult r) => Post(async () =>
    {
        bool wasRunning = transferRunning;
        transferRunning = false;
        transferText.Text = r.Summary;
        double secs = watch.Elapsed.TotalSeconds;
        long done = peer.DoneBytes;
        statsText.Text = wasRunning && done > 0 && secs > 0 ? Util.Bytes(done) + " in " + Util.Duration(secs) + " (" + Util.Bytes((long)(done / secs)) + "/s)" : "";
        if (r.Complete && wasRunning) progress.Value = 1000;
        if (!r.Sending && r.Folder != null)
        {
            lastFolder = r.Folder;
            openBtn.IsVisible = true;
        }
        Refresh();
        if (r.FailedTotal > 0)
        {
            string title = r.Sending ? (peer.PeerName ?? "The other computer") + " couldn't save " + Util.Count(r.FailedTotal, "file", "files") + ":" : "These files couldn't be saved:";
            string text = title + "\n\n" + string.Join("\n", r.Failed.Take(15))
                + (r.FailedTotal > 15 ? "\n…and " + (r.FailedTotal - 15).ToString("N0") + " more (see the log)." : "")
                + "\n\nSending the same files again will retry just these.";
            await Dialogs.Message(this, "Some files failed", text);
        }
    });
}
