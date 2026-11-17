# LAN Drop

Send files and folders straight from one Windows PC to another, on the same network or over the internet. No cloud, no accounts, no size limit.

- **Drag and drop** files or whole folders onto the window. The other person sees the list and total size, picks a folder, and accepts or declines.
- **Every file is checked** with a SHA-256 hash when it arrives. A file that doesn't match is thrown away and reported, never left half-written.
- **Interrupted copies pick up where they stopped.** Send the same files again and the ones already there are skipped.
- **Encrypted** (TLS) on your home network and over the internet.
- **One small `.exe`, nothing to install.** It uses the .NET Framework 4.8 that comes with Windows 10 and 11.

## Download

Get `LanDrop.exe` from the [latest release](../../releases/latest).

Put it in a folder you'll keep it in, such as `Documents\LAN Drop`, before you run it. Firewall rules are tied to the file's location.

Because the app isn't signed, Windows may say **"Windows protected your PC"** the first time. Click **More info → Run anyway**. If you'd rather avoid that, [build it yourself](#building-it-yourself).

## Quick start

Both people open LAN Drop. One PC **waits** and the other **connects**. After that, either side can send.

### On the same network

1. On one PC, click **Wait for connection**. It shows a 6-digit code and its address, "On this network: 192.168.x.x".
2. On the other PC, type that address in **Connect to**, type the code, and click **Connect**.
3. Drop files or folders on the window, or use **Add files…** / **Add folder…**.
4. The other PC chooses where to save, then clicks **Accept**.

The first time a PC clicks **Wait for connection**, Windows asks whether to let LAN Drop through the firewall. Click **Allow**. This needs an admin account.

### Over the internet

1. On the waiting PC, click **Wait for connection**, then **Copy key**.
2. Send the invite key (it starts with `LD1-`) to the other person by Discord, text or email.
3. They paste the whole key into **Connect to** and click **Connect**. No code is needed.

The waiting PC has to be reachable from the internet, so it needs the one-time setup below. **Only the waiting PC needs it.** The PC that connects needs nothing.

## One-time setup for waiting over the internet

### 1. Firewall

Open PowerShell **as administrator** and run this, with the real path to your `LanDrop.exe`:

```powershell
New-NetFirewallRule -DisplayName 'LAN Drop' -Direction Inbound -Action Allow -Program 'C:\path\to\LanDrop.exe' -Protocol TCP -LocalPort 50505 -RemoteAddress Any -Profile Any
```

If you already allowed LAN Drop for your home network only, widen that rule instead:

```powershell
Set-NetFirewallRule -DisplayName 'LAN Drop' -RemoteAddress Any
```

### 2. Router port forward

In your router's settings, usually at `192.168.1.1` or `192.168.0.1`, add a port forward:

| Setting | Value |
|---|---|
| Protocol | TCP |
| External port | 50505 |
| Internal port | 50505 |
| Internal (LAN) address | the address LAN Drop shows under "On this network" |

Also give that PC a **fixed / reserved address** in the router (often called DHCP reservation). Otherwise the forward breaks when the address changes.

### When port forwarding won't work

Some internet providers share one public address between many customers. This is common with mobile hotspots, Starlink and some cable providers, and port forwarding can't work there. One sign: the WAN or Internet address in your router's status page doesn't match the "Internet" address LAN Drop shows.

If that happens:

- **Let the other person wait instead.** Only one of the two PCs has to be reachable.
- **If neither PC can be reached,** install [Tailscale](https://tailscale.com/download) (free) on both PCs and sign them in. LAN Drop treats Tailscale addresses (`100.x.x.x`) like a home network, so connect with the other PC's Tailscale address and the 6-digit code. No port forward is needed.

## Good to know

- **Speed.** On a wired gigabit network, expect around 100 MB/s, which is about 7 minutes for 40 GB. Over the internet, the limit is the sender's upload speed or the receiver's download speed, whichever is slower.
- **Where files go.** Downloads by default, or any folder you choose. A sent folder arrives as a folder with the same name.
- **Name clashes.** If a different file with the same name is already there, the new one is saved as `name (2).ext`. Nothing is overwritten.
- **Resuming.** Leave **Skip files that are already there** ticked when accepting. Files with the same size and date are skipped.
- **Sleep.** The PC stays awake while a transfer is running.
- **Both PCs need the same version.** Version 2 (encrypted, with internet support) can't connect to version 1.

## Security

- LAN Drop only accepts connections **while you've clicked Wait for connection**. At all other times nothing is listening.
- **The 6-digit code only works from the same network** (or Tailscale). Anyone else is turned away. After 5 wrong codes, the code changes.
- **The invite key** carries the waiting PC's addresses, the fingerprint of its encryption certificate, and a random 128-bit secret. The connecting PC refuses any PC whose certificate doesn't match, so nobody can sit in the middle. The waiting PC refuses anyone without the secret.
- **Each key is single-use per wait.** Clicking **Wait for connection** again makes a new key, and old keys stop working.
- **You choose what comes in.** Nothing is saved until you click **Accept**, and incoming file paths can't escape the folder you picked.
- To find its internet address, the waiting PC asks [api.ipify.org](https://www.ipify.org) (or icanhazip.com as a backup). That's the only outside service it contacts.

## Troubleshooting

| Problem | What to check |
|---|---|
| "No answer from …" | Is the other PC still on **Wait for connection**? On the same network, is the address right? Over the internet, are the firewall rule and port forward set up on the waiting PC? |
| "From outside … connect with the invite key" | You're on different networks. Use the invite key instead of the address and code. |
| "That invite key doesn't match" / "isn't the one that made this invite key" | The key is from an earlier wait. Ask for a fresh one. |
| The key only works on the same network | The waiting PC couldn't look up its internet address. The log at the bottom of the window says so. Check its internet connection and click **Wait for connection** again. |
| Some files failed | The list shows why. Send the same files again to retry just those. |

## Building it yourself

You need Windows and nothing else. Download or clone this repository, then run:

```
build.bat
```

That compiles `LanDrop.cs` into `LanDrop.exe` with the C# compiler that ships with Windows (`%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`). A copy you build yourself doesn't trigger the "Windows protected your PC" warning.

## How it works

- **Single file.** One C# WinForms file, `LanDrop.cs`, written in C# 5 so the built-in compiler can build it.
- **Connection.** One TCP connection on port 50505, wrapped in TLS 1.2 with a throwaway self-signed certificate made each time you wait.
- **Messages.** A small message protocol on top: offer, accept/decline, then the file data in 1 MB chunks. Each file ends with its SHA-256 hash.
- **Saving.** The receiver writes to `name.landrop-part`, checks the hash, then renames the file and restores its original modified date.
