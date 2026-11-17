using System.Net;
using System.Net.Sockets;
using System.Text;

namespace LanDrop.Core;

sealed class Connection : IDisposable
{
    readonly TcpClient client;
    public readonly BinaryReader Reader;
    readonly BinaryWriter writer;
    readonly object writeLock = new();
    public string PeerName = "the other PC";
    public readonly string PeerAddress;

    // Socket settings applied before the TLS handshake.
    public static void Prepare(TcpClient c)
    {
        c.NoDelay = true;
        c.ReceiveBufferSize = 1 << 20;
        c.SendBufferSize = 1 << 20;
        c.ReceiveTimeout = 15000; // the handshake must finish in time; cleared once connected
        var s = c.Client;
        // Notice a dead link within about 30 seconds instead of 2 hours.
        try { s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true); } catch { }
        try { s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 15); } catch { }
        try { s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 3); } catch { }
        try { s.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, 5); } catch { }
    }

    // s is the TLS stream on top of c.
    public Connection(TcpClient c, Stream s)
    {
        client = c;
        Reader = new BinaryReader(new BufferedStream(s, 1 << 16), Encoding.UTF8);
        writer = new BinaryWriter(new BufferedStream(s, 1 << 16), Encoding.UTF8);
        var ep = (IPEndPoint)c.Client.RemoteEndPoint;
        PeerAddress = (ep.Address.IsIPv4MappedToIPv6 ? ep.Address.MapToIPv4() : ep.Address).ToString();
    }

    public int ReceiveTimeout { set => client.ReceiveTimeout = value; }

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
