# LAN Drop

Send files and folders straight from one computer to another, on the same network or over the internet. Works on **Windows, Mac and Linux**. No cloud, no accounts, no size limit.

- **Drag and drop** files or whole folders onto the window. The other person sees the list and total size, picks a folder, and accepts or declines.
- **Every file is checked** with a SHA-256 hash when it arrives. A file that doesn't match is thrown away and reported, never left half-written.
- **Interrupted copies pick up where they stopped.** Send the same files again and the ones already there are skipped.
- **Encrypted** (TLS) on your home network and over the internet.
- **Nothing to install.** Each download includes everything it needs.

## Download

Get the file for your computer from the [latest release](../../releases/latest):

| Computer | Download |
|---|---|
| Windows (most PCs) | `LanDrop-Windows-x64.exe` |
| Windows on ARM (Surface Pro X, Snapdragon laptops) | `LanDrop-Windows-arm64.exe` |
| Mac with Apple chip (M1 and later) | `LanDrop-macOS-AppleSilicon.zip` |
| Mac with Intel chip | `LanDrop-macOS-Intel.zip` |
| Linux (most PCs) | `LanDrop-Linux-x64.tar.gz` |
| Linux on ARM (Raspberry Pi 4/5, 64-bit) | `LanDrop-Linux-arm64.tar.gz` |

Not sure which Mac you have? Open the Apple menu → **About This Mac**. "Chip: Apple M…" means Apple chip, and "Processor: Intel" means Intel.

### First run

The downloads aren't signed with a paid Apple or Microsoft certificate, so each system asks you to confirm once.

**Windows**
1. Rename the file to `LanDrop.exe` and move it to a folder you'll keep, such as `Documents\LAN Drop`. Firewall rules are tied to the file's location.
2. Double-click it. If Windows says **"Windows protected your PC"**, click **More info → Run anyway**.

**Mac**
1. Double-click the zip to unpack **LAN Drop**, then drag it into **Applications**.
2. Open it. macOS says it can't check the app for malicious software. Click **Done** (or **OK**).
3. Open **System Settings → Privacy & Security**, scroll down to the message about LAN Drop, and click **Open Anyway**. Confirm with your password.
4. When macOS asks whether LAN Drop may find devices on your local network, click **Allow**. Without this it can't reach the other computer.

On older macOS versions, right-clicking the app and choosing **Open** also works. Or run this in Terminal: `xattr -dr com.apple.quarantine "/Applications/LAN Drop.app"`.

**Linux**
```bash
tar -xzf LanDrop-Linux-x64.tar.gz
./LanDrop
```
It needs a desktop (X11, or Wayland with XWayland) and `fontconfig`, which almost every desktop has. To add it to your app menu, move `LanDrop` somewhere like `~/.local/bin` and create a launcher there.

## Quick start

Both people open LAN Drop. One computer **waits** and the other **connects**. After that, either side can send.

### On the same network

1. On one computer, click **Wait for connection**. It shows a 6-digit code and its address, "On this network: 192.168.x.x".
2. On the other computer, type that address in **Connect to**, type the code, and click **Connect**.
3. Drop files or folders on the window, or use **Add files…** / **Add folder…**.
4. The other computer chooses where to save, then clicks **Accept**.

The first time a computer waits for a connection, its firewall may ask whether to allow LAN Drop. Click **Allow**.

### Over the internet

1. On the waiting computer, click **Wait for connection**, then **Copy key**.
2. Send the invite key (it starts with `LD1-`) to the other person by Discord, text or email.
3. They paste the whole key into **Connect to** and click **Connect**. No code is needed.

The waiting computer has to be reachable from the internet, so it needs the one-time setup below. **Only the waiting computer needs it.** The computer that connects needs nothing.

## One-time setup for waiting over the internet

### 1. Let connections through the firewall

**Windows**: open PowerShell **as administrator** and run this, with the real path to your `LanDrop.exe`:

```powershell
New-NetFirewallRule -DisplayName 'LAN Drop' -Direction Inbound -Action Allow -Program 'C:\path\to\LanDrop.exe' -Protocol TCP -LocalPort 50505 -RemoteAddress Any -Profile Any
```

If you already allowed LAN Drop for your home network only, widen that rule instead:

```powershell
Set-NetFirewallRule -DisplayName 'LAN Drop' -RemoteAddress Any
```

**Mac**: if the firewall is on (System Settings → Network → Firewall), click **Allow** when macOS asks about incoming connections. You can also add LAN Drop under **Options…** there.

**Linux**: most desktops don't block incoming connections. If yours uses `ufw`, run `sudo ufw allow 50505/tcp`. With `firewalld`, run `sudo firewall-cmd --add-port=50505/tcp --permanent && sudo firewall-cmd --reload`.

### 2. Router port forward

In your router's settings, usually at `192.168.1.1` or `192.168.0.1`, add a port forward:

| Setting | Value |
|---|---|
| Protocol | TCP |
| External port | 50505 |
| Internal port | 50505 |
| Internal (LAN) address | the address LAN Drop shows under "On this network" |

Also give that computer a **fixed / reserved address** in the router (often called DHCP reservation). Otherwise the forward breaks when the address changes.

### When port forwarding won't work

Some internet providers share one public address between many customers. This is common with mobile hotspots, Starlink and some cable providers, and port forwarding can't work there. One sign: the WAN or Internet address in your router's status page doesn't match the "Internet" address LAN Drop shows.

If that happens:

- **Let the other person wait instead.** Only one of the two computers has to be reachable.
- **If neither computer can be reached,** install [Tailscale](https://tailscale.com/download) (free) on both and sign them in. LAN Drop treats Tailscale addresses (`100.x.x.x`) like a home network, so connect with the other computer's Tailscale address and the 6-digit code. No port forward is needed.

## Good to know

- **Speed.** On a wired gigabit network, expect around 100 MB/s, which is about 7 minutes for 40 GB. Over the internet, the limit is the sender's upload speed or the receiver's download speed, whichever is slower.
- **Where files go.** Your Downloads folder by default, or any folder you choose. A sent folder arrives as a folder with the same name.
- **Name clashes.** If a different file with the same name is already there, the new one is saved as `name (2).ext`. Nothing is overwritten.
- **Resuming.** Leave **Skip files that are already there** ticked when accepting. Files with the same size and date are skipped.
- **Sleep.** The computer stays awake while a transfer is running.
- **Mixed systems.** Names that Windows can't store (for example `a:b.txt` from a Mac) are adjusted, such as to `a_b.txt`, so files arrive safely on any system. Mac `.DS_Store` files and shortcuts/links aren't sent.
- **Versions.** LAN Drop 3 works with LAN Drop 2.0 for Windows. Version 1 can't connect to either.

## Security

- LAN Drop only accepts connections **while you've clicked Wait for connection**. At all other times nothing is listening.
- **The 6-digit code only works from the same network** (or Tailscale). Anyone else is turned away. After 5 wrong codes, the code changes.
- **The invite key** carries the waiting computer's addresses, the fingerprint of its encryption certificate, and a random 128-bit secret. The connecting computer refuses any computer whose certificate doesn't match, so nobody can sit in the middle. The waiting computer refuses anyone without the secret.
- **Each key is single-use per wait.** Clicking **Wait for connection** again makes a new key, and old keys stop working.
- **You choose what comes in.** Nothing is saved until you click **Accept**, and incoming file paths can't escape the folder you picked.
- To find its internet address, the waiting computer asks [api.ipify.org](https://www.ipify.org) (or icanhazip.com as a backup). That's the only outside service it contacts.

## Troubleshooting

| Problem | What to check |
|---|---|
| "No answer from …" | Is the other computer still on **Wait for connection**? On the same network, is the address right? Over the internet, are the firewall and port forward set up on the waiting computer? On a Mac, is LAN Drop allowed under **Privacy & Security → Local Network**? |
| "From outside … connect with the invite key" | You're on different networks. Use the invite key instead of the address and code. |
| "That invite key doesn't match" / "isn't the one that made this invite key" | The key is from an earlier wait. Ask for a fresh one. |
| The key only works on the same network | The waiting computer couldn't look up its internet address. The log at the bottom of the window says so. Check its internet connection and click **Wait for connection** again. |
| Some files failed | The list shows why. Send the same files again to retry just those. |
| Linux: nothing happens when starting | Run `./LanDrop` from a terminal to see the error. A missing library is usually `libfontconfig1`, `libice6` or `libsm6`. |

## Building it yourself

Install the [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0), then from this folder:

```bash
dotnet run --project src/LanDrop.App          # run the app
dotnet run --project tests/LanDrop.Tests      # run the transfer tests
packaging/publish.sh windows|macos|linux      # build the download files into dist/
```

On Windows, run `publish.sh` from Git Bash. The macOS build has to run on a Mac.

Pushing to GitHub runs the tests on Windows, macOS and Linux, and saves a screenshot of the app from each. Pushing a tag like `v3.0.1` also builds every download and attaches them to a release.

## How it works

| Part | What it is |
|---|---|
| `src/LanDrop.Core` | The transfer engine, with no window code: connections, encryption, invite keys, sending, receiving and checking. |
| `src/LanDrop.App` | The window, built with [Avalonia](https://avaloniaui.net/) so it looks the same on Windows, Mac and Linux. |
| `tests/LanDrop.Tests` | End-to-end tests: two engines send real files to each other over this computer's own network connection. |
| `packaging/` | The icon, the Mac app details and the script that builds the downloads. |

**On the wire:**
- **Connection.** One TCP connection on port 50505, wrapped in TLS with a throwaway self-signed certificate made each time you wait.
- **Messages.** A small message protocol on top: offer, accept/decline, then the file data in 1 MB chunks. Each file ends with its SHA-256 hash.
- **Saving.** The receiver writes to `name.landrop-part`, checks the hash, then renames the file and restores its original modified date.
- **Compatibility.** The protocol is unchanged from LAN Drop 2, which is why the two versions work together.
