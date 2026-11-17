using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;

namespace LanDrop.App;

// Small message and question windows (Avalonia has no built-in message box).
static class Dialogs
{
    public static async Task Message(Window owner, string title, string text) => await Show(owner, title, text, "OK");

    public static async Task<bool> Confirm(Window owner, string title, string text, string yes, string no) =>
        await Show(owner, title, text, yes, no) == yes;

    public static Task<string> Show(Window owner, string title, string text, params string[] buttons)
    {
        var w = new Window
        {
            Title = title,
            Width = 460,
            SizeToContent = SizeToContent.Height,
            CanResize = false,
            ShowInTaskbar = false,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Icon = owner.Icon,
        };
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, HorizontalAlignment = HorizontalAlignment.Right };
        for (int i = 0; i < buttons.Length; i++)
        {
            string label = buttons[i];
            var b = new Button { Content = label, MinWidth = 90, HorizontalContentAlignment = HorizontalAlignment.Center };
            if (i == 0) b.Classes.Add("accent");
            b.Click += (_, _) => w.Close(label);
            row.Children.Add(b);
        }
        w.Content = new StackPanel
        {
            Margin = new Thickness(20),
            Spacing = 18,
            Children =
            {
                new SelectableTextBlock { Text = text, TextWrapping = TextWrapping.Wrap },
                row,
            },
        };
        return w.ShowDialog<string>(owner);
    }
}
