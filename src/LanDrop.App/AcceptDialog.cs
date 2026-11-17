using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Styling;
using LanDrop.Core;

namespace LanDrop.App;

// Shown when the other computer offers files: the list, where to save them, accept or decline.
sealed class AcceptDialog : Window
{
    sealed record Row(string Path, string Size);

    readonly TextBox folderBox;
    readonly TextBlock spaceText;
    readonly CheckBox skipBox;
    readonly long total;

    public AcceptDialog(string peer, Offer offer)
    {
        Title = "Incoming files";
        Width = 620;
        Height = 580;
        MinWidth = 480;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        Topmost = true;
        total = offer.Total;

        var rows = offer.Items.Take(2000).Select(i => new Row(i.RelPath, Util.Bytes(i.Size))).ToList();
        if (offer.Items.Count > 2000) rows.Add(new Row("…and " + (offer.Items.Count - 2000).ToString("N0") + " more", ""));
        var list = new ListBox
        {
            ItemsSource = rows,
            ItemTemplate = new FuncDataTemplate<Row>((r, _) =>
            {
                var g = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
                g.Children.Add(new TextBlock { Text = r?.Path, TextTrimming = TextTrimming.CharacterEllipsis });
                var size = new TextBlock { Text = r?.Size, Margin = new Thickness(12, 0, 0, 0), Opacity = 0.7 };
                Grid.SetColumn(size, 1);
                g.Children.Add(size);
                return g;
            }),
        };
        list.Styles.Add(new Style(x => x.OfType<ListBoxItem>())
        {
            Setters = { new Setter(ListBoxItem.PaddingProperty, new Thickness(10, 3)), new Setter(MinHeightProperty, 0d) },
        });

        folderBox = new TextBox { Text = Util.DefaultSaveFolder() };
        var browse = new Button { Content = "Browse…", Margin = new Thickness(8, 0, 0, 0) };
        var folderRow = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto") };
        folderRow.Children.Add(folderBox);
        Grid.SetColumn(browse, 1);
        folderRow.Children.Add(browse);

        spaceText = new TextBlock { FontSize = 12 };
        skipBox = new CheckBox { IsChecked = true, Content = "Skip files that are already there (same size and date), to finish an earlier copy" };
        var accept = new Button { Content = "Accept", MinWidth = 100, HorizontalContentAlignment = HorizontalAlignment.Center };
        accept.Classes.Add("accent");
        var decline = new Button { Content = "Decline", MinWidth = 100, HorizontalContentAlignment = HorizontalAlignment.Center };

        var top = new StackPanel
        {
            Spacing = 10,
            Children =
            {
                new TextBlock
                {
                    Text = peer + " wants to send you " + Util.Count(offer.Items.Count, "file", "files") + " (" + Util.Bytes(offer.Total) + ").",
                    FontSize = 16, FontWeight = FontWeight.SemiBold, TextWrapping = TextWrapping.Wrap,
                },
            },
        };
        var bottom = new StackPanel
        {
            Spacing = 8,
            Margin = new Thickness(0, 12, 0, 0),
            Children =
            {
                new TextBlock { Text = "Save in this folder:" },
                folderRow,
                spaceText,
                skipBox,
                new TextBlock { Text = "Folders keep their names, so a sent folder arrives as a folder inside this one.", Opacity = 0.7, FontSize = 12, TextWrapping = TextWrapping.Wrap },
                new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 8, 0, 0), Children = { accept, decline } },
            },
        };
        var root = new DockPanel { Margin = new Thickness(20) };
        DockPanel.SetDock(top, Dock.Top);
        DockPanel.SetDock(bottom, Dock.Bottom);
        top.Margin = new Thickness(0, 0, 0, 12);
        root.Children.Add(top);
        root.Children.Add(bottom);
        root.Children.Add(list);
        Content = root;

        folderBox.TextChanged += (_, _) => UpdateSpace();
        browse.Click += async (_, _) =>
        {
            IStorageFolder start = null;
            try { start = await StorageProvider.TryGetFolderFromPathAsync(folderBox.Text); } catch { }
            var picked = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions { Title = "Where should the files go?", SuggestedStartLocation = start });
            var path = picked.FirstOrDefault()?.TryGetLocalPath();
            if (path != null) folderBox.Text = path;
        };
        accept.Click += (_, _) =>
        {
            try
            {
                string f = Path.GetFullPath(Environment.ExpandEnvironmentVariables(ExpandHome(folderBox.Text.Trim())));
                Directory.CreateDirectory(f);
                Close(new AcceptChoice { Folder = f, SkipExisting = skipBox.IsChecked == true });
            }
            catch (Exception ex)
            {
                spaceText.Text = "Can't use that folder: " + ex.Message;
                spaceText.Foreground = Brushes.IndianRed;
            }
        };
        decline.Click += (_, _) => Close(null);
        UpdateSpace();
    }

    static string ExpandHome(string p) =>
        p == "~" || p.StartsWith("~/") ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + p[1..] : p;

    void UpdateSpace()
    {
        var space = Util.FreeSpace(ExpandHome(folderBox.Text ?? ""));
        if (space == null) { spaceText.Text = ""; return; }
        bool enough = space.Value.Free > total;
        spaceText.Text = "Free space on " + space.Value.Disk + ":  " + Util.Bytes(space.Value.Free)
            + (enough ? "" : ". That's not enough for all " + Util.Bytes(total) + ".");
        spaceText.Foreground = enough ? null : Brushes.IndianRed;
        spaceText.Opacity = enough ? 0.75 : 1;
    }
}
