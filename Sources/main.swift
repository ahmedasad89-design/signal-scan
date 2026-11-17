import AppKit
import CoreLocation

final class AppDelegate: NSObject, NSApplicationDelegate, CLLocationManagerDelegate {
    private let location = CLLocationManager()
    private let wifi = WiFiScanner()
    private let ble = BLEScanner()
    private let lan = LANScanner()
    private let air = AirListener()
    private let server = HTTPServer()
    private var window: NSWindow?
    private var statusLabel: NSTextField?
    private var dashboardURL: URL?

    func applicationDidFinishLaunching(_ note: Notification) {
        retireOlderCopies()
        buildMenu()
        buildWindow()

        let args = CommandLine.arguments
        server.webRoot = resolveWebRoot(arguments: args,
                                        builtFrom: Bundle.main.infoDictionary?["SignalScanWebRoot"] as? String,
                                        exists: { FileManager.default.fileExists(atPath: $0) })
        let autoOpen = !args.contains("--no-open")
        server.onCommand = { [weak self] path in
            switch path {
            case "/api/network/trust": self?.lan.setTrusted(true)
            case "/api/network/forget": self?.lan.setTrusted(false)
            case "/api/air/listen": self?.air.listen()
            case "/api/air/read": self?.air.readSnifferFile()
            default: return false
            }
            return true
        }

        air.isTrusted = { [weak self] in self?.lan.trustedNow() ?? false }

        VendorDB.shared.refresh()

        // macOS only reveals Wi-Fi network names to apps allowed to use Location.
        // The location itself is never read or stored.
        location.delegate = self
        publishLocation()
        location.requestWhenInUseAuthorization()

        server.start { [weak self] port in
            DispatchQueue.main.async {
                guard let self = self, let url = URL(string: "http://127.0.0.1:\(port)/") else { return }
                self.dashboardURL = url
                self.statusLabel?.stringValue = "Scanning. The dashboard is at \(url.absoluteString)"
                if autoOpen { NSWorkspace.shared.open(url) }
            }
        }
        wifi.start()
        ble.start()
        lan.start()
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        window?.makeKeyAndOrderFront(nil)
        return true
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) { publishLocation() }

    private func publishLocation() {
        let status: String
        switch location.authorizationStatus {
        case .notDetermined: status = "notDetermined"
        case .restricted: status = "restricted"
        case .denied: status = "denied"
        case .authorizedAlways, .authorizedWhenInUse: status = "authorized"
        @unknown default: status = "unknown"
        }
        Store.shared.set("location", ["status": status])
    }

    /// Only one copy can serve the dashboard's address (127.0.0.1:8377). A copy left running from
    /// an earlier build would keep it, and the open browser tab would go on showing the old build,
    /// so the newest copy asks older ones to quit, and stops any that have not gone after 3 seconds.
    private func retireOlderCopies() {
        let mine = ProcessInfo.processInfo.processIdentifier
        let others = NSRunningApplication
            .runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "dev.local.SignalScan")
            .filter { $0.processIdentifier != mine }
        guard !others.isEmpty else { return }
        func wait(_ seconds: Double) {
            let deadline = Date().addingTimeInterval(seconds)
            while others.contains(where: { !$0.isTerminated }) && Date() < deadline {
                RunLoop.current.run(until: Date().addingTimeInterval(0.1))
            }
        }
        others.forEach { $0.terminate() }
        wait(3)
        others.filter { !$0.isTerminated }.forEach { $0.forceTerminate() }
        wait(2)
    }

    @objc private func openDashboard() {
        if let url = dashboardURL { NSWorkspace.shared.open(url) }
    }

    private func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let menu = NSMenu()
        let open = NSMenuItem(title: "Open Dashboard", action: #selector(openDashboard), keyEquivalent: "o")
        open.target = self
        menu.addItem(open)
        menu.addItem(.separator())
        menu.addItem(NSMenuItem(title: "Quit Signal Scan", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        appItem.submenu = menu
        NSApp.mainMenu = main
    }

    private func buildWindow() {
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 460, height: 150),
                         styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        w.title = "Signal Scan"
        w.isReleasedWhenClosed = false
        let label = NSTextField(wrappingLabelWithString: "Starting the scanner…")
        let hint = NSTextField(wrappingLabelWithString: "Leave this window open while you use the dashboard. Closing it stops the scan.")
        hint.textColor = .secondaryLabelColor
        hint.font = .systemFont(ofSize: 11)
        let button = NSButton(title: "Open Dashboard", target: self, action: #selector(openDashboard))
        button.keyEquivalent = "\r"
        let stack = NSStackView(views: [label, hint, button])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20)
        w.contentView = stack
        w.center()
        w.makeKeyAndOrderFront(nil)
        window = w
        statusLabel = label
    }
}

/// Where dashboard.html is served from: an explicit `--web-root`, else the project folder this
/// build came from (so the page can be edited without rebuilding the app), else the copy
/// inside the app.
func resolveWebRoot(arguments: [String], builtFrom: String?, exists: (String) -> Bool) -> String? {
    if let i = arguments.firstIndex(of: "--web-root"), i + 1 < arguments.count { return arguments[i + 1] }
    if let dir = builtFrom, !dir.isEmpty, exists(dir + "/dashboard.html") { return dir }
    return nil
}

/// `SignalScan --probe 8` runs the Wi-Fi scanner alone for a few seconds and prints what it
/// published. Add `--lan` to run the network-device finder as well: it then reports whether this
/// network is one marked as yours, and searches it only with `--lan-trusted` (use that on your
/// own network only). It opens no window and touches neither Location nor Bluetooth.
func runProbe(seconds: Double, lan: Bool, trusted: Bool) {
    let wifi = WiFiScanner()
    wifi.start()
    let finder = LANScanner()
    if lan {
        finder.start(bonjourTypes: ["_airplay._tcp", "_raop._tcp", "_companion-link._tcp", "_googlecast._tcp",
                                    "_hap._tcp", "_ipp._tcp", "_smb._tcp", "_http._tcp"], searchEverywhere: trusted)
    }
    var stamps = Set<Double>()
    let end = Date().addingTimeInterval(seconds)
    while Date() < end {
        RunLoop.main.run(until: Date().addingTimeInterval(0.2))   // Bonjour reports on the main run loop
        if let state = try? JSONSerialization.jsonObject(with: Store.shared.snapshotJSON()) as? [String: Any],
           let link = state["link"] as? [String: Any], let at = link["at"] as? Double {
            stamps.insert(at)
        }
    }
    print("link samples in \(seconds) s: \(stamps.count)")
    print(String(decoding: Store.shared.snapshotJSON(), as: UTF8.self))
}

/// `SignalScan --selftest` checks the parsers against known inputs, without touching any radio.
func runSelfTest() -> Bool {
    var ok = true
    func check(_ name: String, _ pass: Bool) {
        print(pass ? "ok   " : "FAIL ", name)
        if !pass { ok = false }
    }
    var beacon: [UInt8] = [61, 22, 6, 0x01] + [UInt8](repeating: 0, count: 20)   // HT Operation: second half above
    beacon += [11, 5, 3, 0, 128, 0, 0]                                           // BSS Load: 3 devices, half busy
    beacon += [255, 3, 35, 0, 0]                                                 // HE capabilities
    var wps: [UInt8] = [0x00, 0x50, 0xF2, 0x04, 0x10, 0x21, 0x00, 0x04]
    wps += Array("Acme".utf8)
    wps += [0x10, 0x23, 0x00, 0x03]
    wps += Array("X10".utf8)
    beacon += [221, UInt8(wps.count)] + wps
    beacon += [48, 200, 1, 2]                                                    // truncated element: must not crash
    let ie = parseIEs(Data(beacon))
    check("beacon: 40 MHz second half above", ie.secOffset == 1)
    check("beacon: connected devices", ie.stations == 3)
    check("beacon: airtime busy", abs((ie.utilization ?? 0) - 128.0 / 255.0) < 0.001)
    check("beacon: Wi-Fi 6 flag", ie.wifi6 && !ie.wifi7)
    check("beacon: maker and model", ie.maker == "Acme" && ie.model == "X10")
    check("beacon: empty input", parseIEs(Data()).stations == nil)

    let csv = "Registry,Assignment,Organization Name,Organization Address\n"
        + "MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",\"No.388 Ning Qiao Road Shanghai CN\"\n"
        + "MA-L,0017F2,Apple,1 Infinite Loop Cupertino CA US 95014\n"
    let db = VendorDB.parse(csv)
    check("vendor list: quoted name with a comma", db["286FB9"] == "Nokia Shanghai Bell Co., Ltd.")
    check("vendor list: plain name, header skipped", db["0017F2"] == "Apple" && db.count == 2)
    let placeholders = VendorDB.parse("MA-L,0050C2,IEEE Registration Authority,445 Hoes Lane\nMA-L,00DEAD,Private,\nMA-L,00BEEF,Real Maker Ltd,Somewhere\n")
    check("vendor list: placeholder entries are not makers", placeholders.count == 1 && placeholders["00BEEF"] == "Real Maker Ltd")
    check("page location: explicit folder wins",
          resolveWebRoot(arguments: ["app", "--web-root", "/x"], builtFrom: "/y", exists: { _ in true }) == "/x")
    check("page location: project folder when its page exists",
          resolveWebRoot(arguments: ["app"], builtFrom: "/y", exists: { $0 == "/y/dashboard.html" }) == "/y")
    check("page location: falls back to the copy in the app",
          resolveWebRoot(arguments: ["app"], builtFrom: "/gone", exists: { _ in false }) == nil
          && resolveWebRoot(arguments: ["app", "--web-root"], builtFrom: nil, exists: { _ in true }) == nil)
    // One neighbour record as the kernel lays it out: header, IPv4 address, hardware address.
    var rtm = rt_msghdr()
    rtm.rtm_msglen = UInt16(MemoryLayout<rt_msghdr>.size + 16 + 20)
    rtm.rtm_index = 7
    var sin = sockaddr_in()
    sin.sin_len = 16
    sin.sin_family = sa_family_t(AF_INET)
    sin.sin_addr.s_addr = (ipValue("192.168.1.20") ?? 0).bigEndian
    var record: [UInt8] = withUnsafeBytes(of: &rtm) { Array($0) }
    record += withUnsafeBytes(of: &sin) { Array($0) }
    let linkHead: [UInt8] = [20, UInt8(AF_LINK), 7, 0, 6, 3, 6, 0]
    let linkAddress: [UInt8] = [0x8C, 0x79, 0xF5, 0x00, 0x00, 0x01, 0, 0, 0]
    record += linkHead
    record += Array("en0".utf8)
    record += linkAddress
    let neighbours = parseNeighbours(record + record.prefix(40), count: record.count + 40, ifIndex: 7)
    check("address table: neighbour read, truncated tail ignored",
          neighbours.count == 1 && neighbours[0].ip == "192.168.1.20" && neighbours[0].mac == "8C:79:F5:00:00:01")
    check("address table: other interfaces filtered out", parseNeighbours(record, count: record.count, ifIndex: 3).isEmpty)
    let fn = BonjourWatcher.friendlyName
    check("device names: machine identifiers are not names",
          fn("8c:79:f5:00:00:02@fe80::8e79:f5ff:fe00:2-supportsRP-26", "_apple-mobdev2._tcp.", [:]) == nil
          && fn("01234567-89AB-4CDE-8F01-23456789ABCD", "_hap._tcp.", [:]) == nil
          && fn("8C:79:F5:00:00:01", "_http._tcp.", [:]) == nil)
    check("device names: AirPlay audio name follows the @", fn("A851AB112233@Living Room", "_raop._tcp.", [:])?.name == "Living Room")
    check("device names: cast devices use their friendly name, else lose the id suffix",
          fn("TV55X1-00112233445566778899aabbccddeeff", "_googlecast._tcp.", ["fn": "Lounge TV"])?.name == "Lounge TV"
          && fn("TV55X1-00112233445566778899aabbccddeeff", "_googlecast._tcp.", [:])?.name == "TV55X1")
    check("device names: AirPlay outranks a generic service",
          (fn("Living Room", "_airplay._tcp.", [:])?.rank ?? 9) < (fn("Living Room", "_http._tcp.", [:])?.rank ?? 0))
    // An announcement is a run of entries, each a length byte followed by that many characters.
    // Built in steps: older Swift compilers cannot type-check it as one long expression.
    var announcement: [UInt8] = []
    func entry(_ length: UInt8, _ text: String) {
        announcement.append(length)
        announcement.append(contentsOf: Array(text.utf8))
    }
    entry(5, "fn=TV")
    entry(4, "bare")
    entry(6, "fn=Two")
    announcement.append(0)          // an empty entry
    entry(3, "=no")
    entry(9, "cut")                 // claims more characters than are left
    let txt = BonjourWatcher.attributes(fromTXTRecord: Data(announcement))
    check("device announcements: a key with no value is read as empty, not a crash", txt["fn"] == "TV" && txt["bare"] == "" && txt.count == 2)
    check("private address detection", isPrivateMAC("DA:A1:19:00:00:01") && !isPrivateMAC("00:17:F2:00:00:01"))

    // Listening mode: a small capture built by hand, in both file formats.
    // (Byte arrays are joined with `cat`, and results pulled into plain values before they are
    // compared: older Swift compilers cannot type-check long expressions.)
    func cat(_ parts: [UInt8]...) -> [UInt8] {
        var out: [UInt8] = []
        for part in parts { out += part }
        return out
    }
    func bytes(_ mac: String) -> [UInt8] { mac.split(separator: ":").map { UInt8($0, radix: 16) ?? 0 } }
    func le(_ v: Int, _ n: Int) -> [UInt8] { (0..<n).map { UInt8((v >> (8 * $0)) & 0xFF) } }
    func signed(_ v: Int) -> [UInt8] { [UInt8(bitPattern: Int8(v))] }
    // Radio header with timestamp, flags, rate, channel, strength and noise (24 bytes).
    func radio(_ rssi: Int, _ freq: Int, flags: UInt8 = 0) -> [UInt8] {
        cat([0, 0, 24, 0], le(0x6F, 4), [UInt8](repeating: 0, count: 8), [flags, 12], le(freq, 2), le(0x0140, 2), signed(rssi), signed(-95))
    }
    // The same strength behind a second "fields present" word and an odd alignment (frequency hopping present).
    func radioWide(_ rssi: Int, _ freq: Int) -> [UInt8] {
        cat([0, 0, 32, 0], le(0x8000_003A, 4), le(0x0000_0001, 4), [0, 0], le(freq, 2), le(0x00A0, 2), [7, 9], signed(rssi), [UInt8](repeating: 0xEE, count: 11))
    }
    func frame(_ fc0: UInt8, _ fc1: UInt8, _ a1: String, _ a2: String? = nil, _ a3: String? = nil) -> [UInt8] {
        var f: [UInt8] = [fc0, fc1, 0, 0]
        f += bytes(a1)
        if let a = a2 { f += bytes(a) }
        if let a = a3 {
            f += bytes(a)
            f += [0x10, 0x00, 1, 2, 3, 4]
        }
        return f
    }
    let ap = "8C:79:F5:00:00:10", tv = "8C:79:F5:00:00:20", cam = "54:E0:19:00:00:07", phone = "DA:A1:19:00:00:01"
    let apNext = "B0:95:75:00:00:10", stranger = "3C:22:FB:00:00:99", all = "FF:FF:FF:FF:FF:FF", wired = "00:17:F2:00:00:55"
    var packets: [[UInt8]] = []
    packets.append(cat(radio(-40, 5220), frame(0x80, 0x00, all, ap, ap)))                    // your router's beacon
    packets.append(cat(radio(-52, 5220), frame(0x88, 0x01, ap, tv, wired)))                  // TV to router
    packets.append(cat(radio(-56, 5220), frame(0x88, 0x01, ap, tv, wired)))
    packets.append(cat(radioWide(-50, 5220), frame(0x94, 0x00, ap, tv)))                     // TV acknowledging a burst
    packets.append(cat(radio(-41, 5220), frame(0x88, 0x02, tv, ap, wired)))                  // router to TV: not the TV's signal
    packets.append(cat(radio(-71, 5220), frame(0xB4, 0x00, ap, cam)))                        // camera asking to send, heard once
    packets.append(cat(radio(-63, 5220), frame(0xA4, 0x00, ap, phone)))                      // sleeping phone polling its router
    packets.append(cat(radio(-65, 5220), frame(0x48, 0x01, ap, phone, ap)))                  // phone's "still here" frame
    packets.append(cat(radio(-80, 5220), frame(0x88, 0x01, apNext, stranger, wired)))        // a neighbour's device
    packets.append(cat(radio(-78, 5220), frame(0x88, 0x01, apNext, stranger, wired)))
    packets.append(cat(radio(-60, 5220), frame(0xD4, 0x00, tv)))                             // an acknowledgement names no sender
    packets.append(cat(radio(-30, 5220, flags: 0x40), frame(0x88, 0x01, ap, "02:00:00:00:00:66", wired)))   // arrived damaged
    packets.append(cat(radio(-45, 5220), frame(0x88, 0x01, ap, "03:00:00:00:00:66", wired)))                // a group address cannot send
    packets.append([0, 0, 9, 0, 0, 0, 0, 0, 0])                                              // nonsense: must not crash
    func classicHeader(kind: Int) -> [UInt8] { cat([0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0], le(0, 8), le(256, 4), le(kind, 4)) }
    func classicPacket(_ p: [UInt8]) -> [UInt8] { cat(le(1, 4), le(2, 4), le(p.count, 4), le(p.count, 4), p) }
    var classic: [UInt8] = classicHeader(kind: 127)
    for p in packets { classic += classicPacket(p) }
    func block(_ type: Int, _ body: [UInt8]) -> [UInt8] {
        let padding = [UInt8](repeating: 0, count: (4 - body.count % 4) % 4)
        let size = le(body.count + padding.count + 12, 4)
        return cat(le(type, 4), size, body, padding, size)
    }
    var ng: [UInt8] = block(0x0A0D0D0A, cat(le(0x1A2B3C4D, 4), le(1, 2), le(0, 2), [UInt8](repeating: 0xFF, count: 8)))
    ng += block(1, cat(le(127, 2), le(0, 2), le(256, 4)))
    ng += block(0x8000_0001, [1, 2, 3, 4, 5])                                 // a block kind this reader does not know
    for p in packets { ng += block(6, cat(le(0, 4), le(0, 8), le(p.count, 4), le(p.count, 4), p)) }
    let files: [(String, [UInt8])] = [("capture file", classic), ("pcapng capture file", ng)]
    for (label, file) in files {
        let cap = readCapture(Data(file))
        let allRead = cap.records == packets.count
        let tenGood = cap.frames.count == 10
        check("\(label): every packet read, the unreadable ones dropped", allRead && tenGood && cap.linkType == 127)
        let s = summarise(cap.frames, ownBSSIDs: [ap], known: [cam], selfMAC: nil)
        let devs: [[String: Any]] = (s["devices"] as? [[String: Any]]) ?? []
        var byMAC: [String: [String: Any]] = [:]
        var order: [String] = []
        for d in devs {
            let mac = (d["mac"] as? String) ?? ""
            byMAC[mac] = d
            order.append(mac)
        }
        func value(_ mac: String, _ key: String) -> Int { (byMAC[mac]?[key] as? Int) ?? 0 }
        check("\(label): your devices, strongest first", order == [tv, phone, cam])
        let tvRight = value(tv, "rssi") == -52 && value(tv, "best") == -50
        check("\(label): TV strength is the middle of its own frames only", tvRight && value(tv, "frames") == 3)
        let phoneRouter = (byMAC[phone]?["bssid"] as? String) ?? ""
        check("\(label): channel and router", value(tv, "channel") == 44 && value(tv, "band") == 5 && phoneRouter == ap)
        let camListed = (byMAC[cam]?["listed"] as? Bool) ?? false
        check("\(label): a listed device counts on one frame", value(cam, "frames") == 1 && camListed)
        let others: [String: Any] = (s["others"] as? [String: Any]) ?? [:]
        let otherCount = (others["devices"] as? Int) ?? 0
        let otherBest = (others["strongest"] as? Int) ?? 0
        let unnamed = byMAC[stranger] == nil && byMAC[ap] == nil
        check("\(label): a neighbour's device is counted, never named", otherCount == 1 && otherBest == -78 && unnamed)
    }
    let cutShort = readCapture(Data(classic.dropLast(7))).frames.count
    let headerOnly = readCapture(Data(classic.prefix(30))).frames.count
    check("capture file: cut off mid-packet", cutShort == 10 && headerOnly == 0)
    let bare: [UInt8] = cat(classicHeader(kind: 105), classicPacket(frame(0x88, 0x01, ap, tv, wired)))
    check("capture file: no radio header means no strengths", readCapture(Data(bare)).problem != nil)
    let junk = readCapture(Data([UInt8](repeating: 7, count: 64)))
    check("capture file: not a capture", junk.problem != nil && readCapture(Data()).frames.isEmpty)
    let ch6 = channelNumber(mhz: 2437), ch44 = channelNumber(mhz: 5220), ch37 = channelNumber(mhz: 6135)
    let numbersRight = ch6?.channel == 6 && ch44?.channel == 44 && ch37?.channel == 37
    check("channel numbers", numbersRight && ch37?.band == 6 && channelNumber(mhz: 900) == nil)
    check("address maths", ipValue("192.168.1.233") == 0xC0A8_01E9 && ipString(0xC0A8_0101) == "192.168.1.1")
    return ok
}

if CommandLine.arguments.contains("--selftest") {
    exit(runSelfTest() ? 0 : 1)
}
if let i = CommandLine.arguments.firstIndex(of: "--air"), i + 1 < CommandLine.arguments.count {
    var own: Set<String> = []
    if let j = CommandLine.arguments.firstIndex(of: "--own"), j + 1 < CommandLine.arguments.count {
        for part in CommandLine.arguments[j + 1].uppercased().split(separator: ",") { own.insert(String(part)) }
    }
    runAirReport(path: CommandLine.arguments[i + 1], own: own)
    exit(0)
}
if let i = CommandLine.arguments.firstIndex(of: "--probe") {
    let seconds = i + 1 < CommandLine.arguments.count ? Double(CommandLine.arguments[i + 1]) ?? 8 : 8
    let trusted = CommandLine.arguments.contains("--lan-trusted")
    runProbe(seconds: min(max(seconds, 2), 60), lan: trusted || CommandLine.arguments.contains("--lan"), trusted: trusted)
    exit(0)
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
