import Foundation
import CoreWLAN

// Listening mode ("monitor mode"). For a few seconds the Mac's Wi-Fi card stops being a member
// of the network and simply hears every Wi-Fi frame on a channel, each with the strength it
// arrived at. It is the only way to hear the devices themselves (TV, cameras, phones) rather
// than just the routers, which is all an ordinary scan reports.
//
// Three rules shape this file:
//   - It only ever runs on a network the user has marked as their own. Listening hears every
//     device in range, so it is not something to do in an office or a public place.
//   - The capture itself is done by macOS's own tcpdump, started through the system's password
//     prompt. Nothing of ours runs as root, and tcpdump gives up its privileges before it
//     writes the file.
//   - Only the first bytes of each frame are kept (addresses and signal strength, never
//     content), the file is deleted as soon as it has been read, and addresses of devices on
//     other people's networks are never published: they are only counted.

/// One Wi-Fi frame as heard: who sent it, to whom, for which network, and how strongly.
struct AirFrame: Equatable {
    var ta: String          // the transmitter, whose signal strength this is
    var ra: String          // the receiver
    var bssid: String?      // the router (network) the frame belongs to, when the frame says
    var fromAP: Bool        // sent by a router rather than by a device
    var rssi: Int           // dBm
    var freq: Int           // MHz
}

struct Capture {
    var frames: [AirFrame] = []
    var records = 0          // packets in the file
    var linkType: Int?       // 127 = 802.11 with a radio header, the only kind that carries strengths
    var problem: String?
}

// Numbers in a capture are stored low byte first or high byte first, depending on who wrote it.
// (Written as loops, one small step at a time: older Swift compilers give up on long expressions.)
private func number(_ b: [UInt8], _ i: Int, bytes: Int, big: Bool) -> Int {
    var v = 0
    for k in 0..<bytes {
        let at = big ? i + k : i + bytes - 1 - k
        v = (v << 8) | Int(b[at])
    }
    return v
}
private func le16(_ b: [UInt8], _ i: Int) -> Int { number(b, i, bytes: 2, big: false) }
private func word(_ b: [UInt8], _ i: Int, big: Bool) -> Int { number(b, i, bytes: 4, big: big) }
private func half(_ b: [UInt8], _ i: Int, big: Bool) -> Int { number(b, i, bytes: 2, big: big) }
private let pcapngMagic: [UInt8] = [0x0A, 0x0D, 0x0D, 0x0A]
private let pcapLittle: [[UInt8]] = [[0xD4, 0xC3, 0xB2, 0xA1], [0x4D, 0x3C, 0xB2, 0xA1]]
private let pcapBig: [[UInt8]] = [[0xA1, 0xB2, 0xC3, 0xD4], [0xA1, 0xB2, 0x3C, 0x4D]]
private func macString(_ b: [UInt8], _ i: Int) -> String {
    (0..<6).map { String(format: "%02X", b[i + $0]) }.joined(separator: ":")
}

/// The radio header macOS puts in front of each frame. Only the leading fields are needed
/// (flags, channel, signal strength); they come in a fixed order, each on its own alignment.
func parseRadiotap(_ b: [UInt8], from start: Int, to end: Int) -> (length: Int, rssi: Int?, freq: Int?, flags: UInt8)? {
    guard end - start >= 8, b[start] == 0 else { return nil }
    let length = le16(b, start + 2)
    guard length >= 8, start + length <= end else { return nil }
    let stop = start + length
    // One or more words say which fields are present; bit 31 means another word follows.
    var p = start + 4
    let present = word(b, p, big: false)
    var more = present
    while true {
        p += 4
        if more & 0x8000_0000 == 0 { break }
        guard p + 4 <= stop else { return nil }
        more = word(b, p, big: false)
    }
    var off = p - start
    func align(_ n: Int) { off = (off + n - 1) / n * n }
    var rssi: Int?, freq: Int?, flags: UInt8 = 0
    if present & 0x01 != 0 { align(8); off += 8 }                                   // timestamp
    if present & 0x02 != 0 { guard start + off < stop else { return nil }; flags = b[start + off]; off += 1 }
    if present & 0x04 != 0 { off += 1 }                                             // rate
    if present & 0x08 != 0 {                                                        // channel: frequency, then flags
        align(2)
        guard start + off + 4 <= stop else { return nil }
        freq = le16(b, start + off)
        off += 4
    }
    if present & 0x10 != 0 { align(2); off += 2 }                                   // frequency hopping
    if present & 0x20 != 0 {                                                        // signal strength in dBm
        guard start + off < stop else { return nil }
        rssi = Int(Int8(bitPattern: b[start + off]))
    }
    return (length, rssi, freq, flags)
}

/// The start of a Wi-Fi frame: which addresses are in it depends on the kind of frame.
func parse80211(_ b: [UInt8], from start: Int, to end: Int) -> (ta: String, ra: String, bssid: String?, fromAP: Bool)? {
    guard end - start >= 16 else { return nil }
    let fc0 = b[start], fc1 = b[start + 1]
    guard fc0 & 0x03 == 0 else { return nil }                 // protocol version is always 0
    let type = (fc0 >> 2) & 3, sub = fc0 >> 4
    guard b[start + 10] & 0x01 == 0 else { return nil }       // a transmitter is one device, never a group
    let ra = macString(b, start + 4), ta = macString(b, start + 10)
    guard ta != "00:00:00:00:00:00" else { return nil }
    let everyone = "FF:FF:FF:FF:FF:FF"
    switch type {
    case 0:                                                   // management: beacons, joining, probing
        guard end - start >= 24 else { return nil }
        let third = macString(b, start + 16)
        return (ta, ra, third == everyone ? nil : third, sub == 8 || sub == 5)
    case 2:                                                   // data
        guard end - start >= 24 else { return nil }
        switch fc1 & 0x03 {
        case 0x01: return (ta, ra, ra, false)                 // device to router
        case 0x02: return (ta, ra, ta, true)                  // router to device
        case 0x00: return (ta, ra, macString(b, start + 16), false)
        default: return (ta, ra, nil, false)                  // router to router
        }
    case 1:                                                   // control: only some kinds name their sender
        switch sub {
        case 10: return (ta, ra, ra, false)                   // a sleeping device asking its router for data
        case 2, 14, 15: return (ta, ra, ta, true)             // sent by routers
        case 4, 5, 8, 9, 11: return (ta, ra, nil, false)      // either side: the receiver tells which
        default: return nil                                   // acknowledgements carry no sender
        }
    default:
        return nil
    }
}

/// Reads a capture file (the classic format or the newer "pcapng") into frames.
func readCapture(_ data: Data) -> Capture {
    let b = [UInt8](data)
    var out = Capture()
    func take(_ start: Int, _ end: Int, link: Int) {
        out.records += 1
        if out.linkType == nil || link == 127 { out.linkType = link }
        guard link == 127, let radio = parseRadiotap(b, from: start, to: end) else { return }
        guard radio.flags & 0x40 == 0 else { return }          // arrived damaged: its addresses cannot be trusted
        guard let rssi = radio.rssi, rssi < 0, rssi >= -110, let freq = radio.freq else { return }
        guard let f = parse80211(b, from: start + radio.length, to: end) else { return }
        out.frames.append(AirFrame(ta: f.ta, ra: f.ra, bssid: f.bssid, fromAP: f.fromAP, rssi: rssi, freq: freq))
    }
    guard b.count >= 24 else { out.problem = "The capture is empty."; return out }
    let magic: [UInt8] = Array(b[0..<4])
    if magic == pcapngMagic {
        // pcapng: a chain of blocks, each "type, length, body, length".
        var big = false
        var links: [Int] = []
        var p = 0
        while p + 12 <= b.count {
            let isHeader = Array(b[p..<p + 4]) == pcapngMagic
            if isHeader {
                big = b[p + 8] == 0x1A
                links = []
            }
            let type = word(b, p, big: big), length = word(b, p + 4, big: big)
            guard length >= 12, length % 4 == 0, p + length <= b.count else { break }
            let body = p + 8, bodyEnd = p + length - 4
            if isHeader {
                // nothing else in it matters here
            } else if type == 1, bodyEnd - body >= 8 {            // an interface, and the kind of frames it yields
                links.append(half(b, body, big: big))
            } else if type == 6, bodyEnd - body >= 20 {           // a packet
                let iface = word(b, body, big: big), got = word(b, body + 12, big: big)
                if iface >= 0, iface < links.count, got >= 0, body + 20 + got <= bodyEnd { take(body + 20, body + 20 + got, link: links[iface]) }
            } else if type == 2, bodyEnd - body >= 20 {           // the older packet block
                let iface = half(b, body, big: big), got = word(b, body + 12, big: big)
                if iface < links.count, got >= 0, body + 20 + got <= bodyEnd { take(body + 20, body + 20 + got, link: links[iface]) }
            } else if type == 3, bodyEnd - body >= 4, let link = links.first {   // a packet with no extras
                take(body + 4, bodyEnd, link: link)
            }
            p += length
        }
    } else {
        let big = pcapBig.contains(magic)
        guard big || pcapLittle.contains(magic) else {
            out.problem = "This is not a capture file Signal Scan can read."
            return out
        }
        let link = word(b, 20, big: big) & 0xFFFF
        var p = 24
        while p + 16 <= b.count {
            let got = word(b, p + 8, big: big)
            guard got >= 0, p + 16 + got <= b.count else { break }   // a file cut off mid-packet
            take(p + 16, p + 16 + got, link: link)
            p += 16 + got
        }
    }
    if out.records > 0, out.linkType != 127 {
        out.problem = "The capture has no signal strengths in it (it was not taken in listening mode)."
    }
    return out
}

func channelNumber(mhz f: Int) -> (channel: Int, band: Int)? {
    if f == 2484 { return (14, 2) }
    if f >= 2412, f <= 2472 { return ((f - 2407) / 5, 2) }
    if f >= 5160, f <= 5885 { return ((f - 5000) / 5, 5) }
    if f >= 5955, f <= 7115 { return ((f - 5950) / 5, 6) }
    return nil
}

/// Turns the frames into the list the dashboard shows: your own devices with how strongly each
/// arrived, and a bare count of everything else.
///   - ownBSSIDs: the radio addresses of your own routers.
///   - known: addresses already listed as joined to your network.
func summarise(_ frames: [AirFrame], ownBSSIDs: Set<String>, known: Set<String>, selfMAC: String?) -> [String: Any] {
    // Anything that sends beacons, or that devices address as their router, is a router.
    var routers = ownBSSIDs
    for f in frames {
        if f.fromAP { routers.insert(f.ta) }
        if let b = f.bssid { routers.insert(b) }
    }
    struct Tally { var rssi: [Int] = []; var freq: [Int: Int] = [:]; var votes: [String: Int] = [:] }
    var senders: [String: Tally] = [:]
    var perFreq: [Int: Int] = [:]
    for f in frames {
        perFreq[f.freq, default: 0] += 1
        guard !routers.contains(f.ta), f.ta != selfMAC else { continue }
        var t = senders[f.ta] ?? Tally()
        t.rssi.append(f.rssi)
        t.freq[f.freq, default: 0] += 1
        if let b = f.bssid ?? (routers.contains(f.ra) ? f.ra : nil) { t.votes[b, default: 0] += 1 }
        senders[f.ta] = t
    }
    var devices: [[String: Any]] = []
    var others = 0
    var othersBest: Int?
    for (mac, t) in senders {
        let sorted = t.rssi.sorted()
        let median = sorted[sorted.count / 2], best = sorted[sorted.count - 1]
        let ranked = t.votes.sorted { a, b in
            if a.value != b.value { return a.value > b.value }
            return a.key < b.key
        }
        let router = ranked.first?.key
        let listed = known.contains(mac)
        let yours = listed || (router.map { ownBSSIDs.contains($0) } ?? false)
        // One stray frame can be a mis-heard address; a device already on your list needs no second.
        guard sorted.count >= 2 || listed else { continue }
        if yours {
            var d: [String: Any] = ["mac": mac, "rssi": median, "best": best, "frames": sorted.count, "listed": listed]
            if let f = t.freq.max(by: { $0.value < $1.value })?.key, let ch = channelNumber(mhz: f) {
                d["channel"] = ch.channel
                d["band"] = ch.band
            }
            if let r = router { d["bssid"] = r }
            devices.append(d)
        } else {
            others += 1
            othersBest = max(othersBest ?? -200, median)
        }
    }
    devices.sort { a, b in
        let ra = (a["rssi"] as? Int) ?? -200
        let rb = (b["rssi"] as? Int) ?? -200
        if ra != rb { return ra > rb }
        let ma = (a["mac"] as? String) ?? ""
        let mb = (b["mac"] as? String) ?? ""
        return ma < mb
    }
    var channels: [[String: Any]] = []
    for (f, n) in perFreq.sorted(by: { $0.value > $1.value }) {
        if let ch = channelNumber(mhz: f) { channels.append(["channel": ch.channel, "band": ch.band, "frames": n]) }
    }
    var result: [String: Any] = ["devices": devices, "frames": frames.count, "channels": channels, "others": ["devices": others]]
    if let b = othersBest { result["others"] = ["devices": others, "strongest": b] }
    return result
}

final class AirListener {
    /// Asks, at this moment, whether the network this Mac is on is one marked as the user's own.
    var isTrusted: (() -> Bool)?

    private let queue = DispatchQueue(label: "signalscan.air", qos: .userInitiated)
    private var busy = false                 // only touched on `queue`
    private var lastResult: [String: Any]?
    private let dwell = 8.0                  // seconds spent on each channel
    private let maxChannels = 4

    init() { publish("idle") }

    /// The dashboard's "Listen" button.
    func listen() { queue.async { self.once { self.capture() } } }

    /// The dashboard's "read a Wireless Diagnostics capture" link: for Macs where the automatic
    /// way does not work, Apple's own Sniffer can make the capture and this reads it.
    func readSnifferFile() { queue.async { self.once { self.readNewestFile() } } }

    private func once(_ work: () -> Void) {
        guard !busy else { return }
        busy = true
        work()
        busy = false
    }

    private func publish(_ state: String, step: String? = nil, error: String? = nil) {
        var section: [String: Any] = ["state": state, "since": now()]
        if let s = step { section["step"] = s }
        if let e = error { section["error"] = e }
        if let r = lastResult { section["result"] = r }
        Store.shared.set("air", section)
    }

    /// The routers of the network this Mac is on, from the last ordinary scan.
    private func ownNetwork() -> (bssids: Set<String>, plan: [(channel: Int, band: Int, width: Int)])? {
        guard let wifi = Store.shared.get("wifi") as? [String: Any],
              let iface = wifi["iface"] as? [String: Any],
              let ssid = iface["ssid"] as? String, let live = iface["bssid"] as? String else { return nil }
        let all: [[String: Any]] = (wifi["networks"] as? [[String: Any]]) ?? []
        var nets: [[String: Any]] = all.filter { ($0["ssid"] as? String) == ssid }
        nets.sort { a, b in
            let ra = (a["rssi"] as? Int) ?? -200
            let rb = (b["rssi"] as? Int) ?? -200
            return ra > rb
        }
        var bssids = Set(nets.compactMap { $0["bssid"] as? String })
        bssids.insert(live)
        // The channel this Mac is on first, then the network's other radios, strongest first.
        var plan: [(channel: Int, band: Int, width: Int)] = []
        var candidates: [[String: Any]] = [iface]
        candidates += nets
        for n in candidates {
            guard let c = n["channel"] as? Int, let band = n["band"] as? Int else { continue }
            let width = (n["width"] as? Int) ?? 20
            let already = plan.contains { $0.channel == c && $0.band == band }
            if !already { plan.append((c, band, width)) }
        }
        return (bssids, Array(plan.prefix(maxChannels)))
    }

    private func knownAddresses() -> Set<String> {
        let lan = Store.shared.get("lan") as? [String: Any]
        return Set(((lan?["devices"] as? [[String: Any]]) ?? []).compactMap { $0["mac"] as? String })
    }

    private func finish(_ capture: Capture, own: Set<String>, source: String, seconds: Double?, note: String?, selfMAC: String?) {
        if capture.frames.isEmpty {
            let why = capture.problem ?? (capture.records == 0
                ? "Listening mode started, but the Wi-Fi card handed over nothing. macOS may not allow it on this Mac."
                : "Frames were heard, but none could be read.")
            publish("error", error: why)
            return
        }
        var result = summarise(capture.frames, ownBSSIDs: own, known: knownAddresses(), selfMAC: selfMAC)
        // Maker and address kind, so a device that is not in the joined list can still be described.
        result["devices"] = ((result["devices"] as? [[String: Any]]) ?? []).map { d -> [String: Any] in
            var d = d
            guard let mac = d["mac"] as? String else { return d }
            d["private"] = isPrivateMAC(mac)
            if let v = VendorDB.shared.lookup(mac: mac) { d["vendor"] = v }
            return d
        }
        result["at"] = now()
        result["source"] = source
        if let s = seconds { result["seconds"] = Int(s.rounded()) }
        if let n = note { result["note"] = n }
        lastResult = result
        publish("done")
    }

    private func capture() {
        guard isTrusted?() == true else {
            publish("error", error: "Listening only runs on a network you have marked as your own. It hears every device in range, which is not something to do at an office or in a public place.")
            return
        }
        guard let iface = CWWiFiClient.shared().interface(), let ifname = iface.interfaceName, iface.powerOn() else {
            publish("error", error: "Wi-Fi is turned off.")
            return
        }
        guard let network = ownNetwork(), !network.plan.isEmpty else {
            publish("error", error: "Signal Scan cannot tell which routers are yours yet. Allow Location, wait for a Wi-Fi scan, and try again.")
            return
        }
        // These three go into a command line run with administrator rights, so each must be
        // exactly what it is expected to be.
        let user = NSUserName()
        let plain = "^[A-Za-z0-9._-]+$"
        guard ifname.range(of: "^en[0-9]+$", options: .regularExpression) != nil,
              user.range(of: plain, options: .regularExpression) != nil,
              let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            publish("error", error: "This Mac's account or Wi-Fi interface has a name Signal Scan does not handle.")
            return
        }
        let dir = support.appendingPathComponent("SignalScan/air", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let name = "listen-\(UUID().uuidString).pcap"
        let path = dir.appendingPathComponent(name).path
        guard !path.contains("'"), !path.contains("\\"), !path.contains("\"") else {
            publish("error", error: "This Mac's home folder has a name Signal Scan does not handle.")
            return
        }
        defer { try? FileManager.default.removeItem(atPath: path) }

        // macOS's own capture tool, in listening mode, keeping only the first 256 bytes of each
        // frame. It drops its administrator rights (-Z) before it creates the file. A watchdog
        // stops it even if this app has gone away, so the Mac is never left off its Wi-Fi.
        let total = Double(network.plan.count) * dwell
        let limit = Int(total) + 25
        let command = "/usr/sbin/tcpdump -I -i \(ifname) -y IEEE802_11_RADIO -s 256 -c 400000 -Z \(user) -w '\(path)' 2>&1 & p=$!; "
            + "( /bin/sleep \(limit); /bin/kill -INT $p ) >/dev/null 2>&1 & w=$!; wait $p; /bin/kill $w >/dev/null 2>&1; exit 0"
        let prompt = "Signal Scan wants to listen for your devices’ Wi-Fi for about \(Int(total)) seconds. This Mac drops off Wi-Fi while it listens."
        var quoted = command.replacingOccurrences(of: "\\", with: "\\\\")
        quoted = quoted.replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(quoted)\" with prompt \"\(prompt)\" with administrator privileges"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", script]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch {
            publish("error", error: "Could not ask for your password: \(error.localizedDescription)")
            return
        }
        publish("password", step: "Waiting for your password")

        // The file appears once the card is in listening mode: that is the starting gun.
        let giveUp = now() + 180
        while p.isRunning, !FileManager.default.fileExists(atPath: path), now() < giveUp { usleep(200_000) }
        guard FileManager.default.fileExists(atPath: path) else {
            if p.isRunning { p.terminate() }
            p.waitUntilExit()
            let said = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            let lower = said.lowercased()
            let timedOut = now() >= giveUp
            let dismissed = said.contains("-128") || lower.contains("cancel")
            let unsupported = lower.contains("monitor mode") || lower.contains("not supported")
            if dismissed || timedOut {
                publish("idle")                                  // the password prompt was dismissed
            } else if unsupported {
                publish("error", error: "macOS says this Mac's Wi-Fi card cannot be put in listening mode.")
            } else {
                let lastLine = said.split(separator: "\n").last
                var line = ""
                if let last = lastLine { line = String(last) }
                var why = "Listening could not start."
                if !line.isEmpty { why += " macOS said: \(line.prefix(160))" }
                publish("error", error: why)
            }
            return
        }

        Store.shared.listening = true                            // the ordinary scans stand down meanwhile
        defer { Store.shared.listening = false }
        let started = now()
        let selfMAC = iface.hardwareAddress()?.uppercased()
        iface.disassociate()
        var stuck: String?
        for (i, hop) in network.plan.enumerated() where p.isRunning {
            publish("listening", step: "Listening on channel \(hop.channel) (\(i + 1) of \(network.plan.count))")
            if let ch = pick(iface, hop) {
                do { try iface.setWLANChannel(ch) } catch { stuck = "macOS did not let Signal Scan change channel, so only one channel was heard." }
            }
            let until = now() + dwell
            while p.isRunning, now() < until { usleep(200_000) }
        }
        // tcpdump now runs as this user, so this app may stop it. The watchdog is the fallback.
        for line in run("/usr/bin/pgrep", ["-f", name]).split(separator: "\n") {
            if let pid = Int32(line.trimmingCharacters(in: .whitespaces)), pid > 1 { kill(pid, SIGINT) }
        }
        let patience = now() + Double(limit)
        while p.isRunning, now() < patience { usleep(200_000) }
        if p.isRunning { p.terminate() }
        let heardFor = now() - started

        publish("reading", step: "Rejoining your Wi-Fi")
        let back = rejoin(iface)
        let data = FileManager.default.contents(atPath: path) ?? Data()
        var note = stuck
        if !back { note = (note.map { $0 + " " } ?? "") + "This Mac did not rejoin your Wi-Fi by itself: choose your network from the Wi-Fi menu." }
        finish(readCapture(data), own: network.bssids, source: "listen", seconds: heardFor, note: note, selfMAC: selfMAC)
    }

    /// The channel object CoreWLAN wants: same number and band, as wide as the network if it can be.
    private func pick(_ iface: CWInterface, _ hop: (channel: Int, band: Int, width: Int)) -> CWChannel? {
        let bandOf: [Int: Int] = [1: 2, 2: 5, 3: 6]
        let widthOf: [Int: Int] = [1: 20, 2: 40, 3: 80, 4: 160]
        var best: CWChannel?        // the widest that is no wider than the network
        var narrowest: CWChannel?   // otherwise the narrowest there is
        var bestWidth = 0, narrowestWidth = Int.max
        for ch in iface.supportedWLANChannels() ?? [] {
            guard ch.channelNumber == hop.channel, bandOf[ch.channelBand.rawValue] == hop.band else { continue }
            let w = widthOf[ch.channelWidth.rawValue] ?? 20
            if w <= hop.width, w > bestWidth { best = ch; bestWidth = w }
            if w < narrowestWidth { narrowest = ch; narrowestWidth = w }
        }
        return best ?? narrowest
    }

    /// After listening the card normally rejoins by itself. If it has not, switching Wi-Fi off
    /// and on makes macOS join the usual network again.
    private func rejoin(_ iface: CWInterface) -> Bool {
        func joined(within seconds: Double) -> Bool {
            let until = now() + seconds
            while now() < until {
                if iface.ssid() != nil || iface.rssiValue() != 0 { return true }
                usleep(500_000)
            }
            return false
        }
        if joined(within: 15) { return true }
        try? iface.setPower(false)
        usleep(1_500_000)
        try? iface.setPower(true)
        return joined(within: 25)
    }

    private func readNewestFile() {
        guard isTrusted?() == true else {
            publish("error", error: "Captures are only read on a network you have marked as your own.")
            return
        }
        guard let network = ownNetwork() else {
            publish("error", error: "Signal Scan cannot tell which routers are yours yet. Allow Location, wait for a Wi-Fi scan, and try again.")
            return
        }
        // Wireless Diagnostics saves its Sniffer captures here.
        let folder = "/private/var/tmp"
        var newest: (path: String, at: Date)?
        for file in (try? FileManager.default.contentsOfDirectory(atPath: folder)) ?? [] {
            guard file.hasSuffix(".pcap") || file.hasSuffix(".pcapng") || file.hasSuffix(".wcap") else { continue }
            let path = folder + "/" + file
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                  let at = attrs[.modificationDate] as? Date, at.timeIntervalSinceNow > -7200 else { continue }
            if newest == nil || at > newest!.at { newest = (path, at) }
        }
        guard let found = newest else {
            publish("error", error: "No capture from the last two hours was found. In Wireless Diagnostics choose Window, then Sniffer, pick your channel, start it, wait half a minute and stop it.")
            return
        }
        publish("reading", step: "Reading the capture")
        guard let handle = FileHandle(forReadingAtPath: found.path) else {
            publish("error", error: "macOS did not let Signal Scan open the capture.")
            return
        }
        let data = handle.readData(ofLength: 96 * 1024 * 1024)       // plenty for a few minutes of headers
        try? handle.close()
        let selfMAC = CWWiFiClient.shared().interface()?.hardwareAddress()?.uppercased()
        finish(readCapture(data), own: network.bssids, source: "file", seconds: nil, note: nil, selfMAC: selfMAC)
    }
}

/// `SignalScan --air capture.pcap [--own AA:BB:CC:DD:EE:FF,…]` reads a capture file and prints
/// what was heard, without touching any radio. For checking a capture by hand.
func runAirReport(path: String, own: Set<String>) {
    guard let data = FileManager.default.contents(atPath: path) else {
        print("cannot read \(path)")
        return
    }
    let cap = readCapture(data)
    let kind = cap.linkType.map { String($0) } ?? "none"
    print("packets \(cap.records) · kind \(kind) · frames with a sender and a strength \(cap.frames.count)")
    if let p = cap.problem { print("problem: \(p)") }
    let s = summarise(cap.frames, ownBSSIDs: own, known: [], selfMAC: nil)
    for c in (s["channels"] as? [[String: Any]]) ?? [] {
        print("channel \(c["channel"] ?? "?") (\(c["band"] ?? "?") GHz): \(c["frames"] ?? 0) frames")
    }
    for d in (s["devices"] as? [[String: Any]]) ?? [] {
        print("yours  \(d["mac"] ?? "") \(d["rssi"] ?? 0) dBm (best \(d["best"] ?? 0)) · \(d["frames"] ?? 0) frames · channel \(d["channel"] ?? "?") · router \(d["bssid"] ?? "?")")
    }
    let others = s["others"] as? [String: Any]
    print("others \(others?["devices"] ?? 0) devices" + ((others?["strongest"]).map { ", strongest \($0) dBm" } ?? ""))
}
