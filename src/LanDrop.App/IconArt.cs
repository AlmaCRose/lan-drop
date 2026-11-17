using Avalonia;
using Avalonia.Media;
using Avalonia.Media.Imaging;

namespace LanDrop.App;

// The app icon: a rounded blue square with an arrow dropping onto a line.
// Drawn in code; packaging/icon.png is made from it with --write-icon.
static class IconArt
{
    public static RenderTargetBitmap Render(int size)
    {
        var bmp = new RenderTargetBitmap(new PixelSize(size, size));
        double k = size / 128.0;
        using (var ctx = bmp.CreateDrawingContext())
        using (ctx.PushTransform(Matrix.CreateScale(k, k)))
        {
            var fill = new LinearGradientBrush
            {
                StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
                EndPoint = new RelativePoint(0, 1, RelativeUnit.Relative),
                GradientStops = { new GradientStop(Color.FromRgb(0x3B, 0x82, 0xF6), 0), new GradientStop(Color.FromRgb(0x1D, 0x4E, 0xD8), 1) },
            };
            ctx.DrawRectangle(fill, null, new RoundedRect(new Rect(6, 6, 116, 116), 26));
            var pen = new Pen(Brushes.White, 11, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);
            ctx.DrawLine(pen, new Point(64, 28), new Point(64, 80));
            ctx.DrawGeometry(null, pen, Geometry.Parse("M 42,60 L 64,82 L 86,60"));
            ctx.DrawLine(pen, new Point(36, 100), new Point(92, 100));
        }
        return bmp;
    }
}
