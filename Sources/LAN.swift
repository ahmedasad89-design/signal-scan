import Foundation

/// Collects the names devices announce about themselves on the local network
/// (Bonjour): "Living Room TV", printers, speakers, smart-home hubs.
final class BonjourWatcher: NSObject, NetServiceBrowserDelegate, NetServiceDelegate {
    struct Info {
        var name: String?
        var nameRank = Int.max
        var model: String?
        var types: Set<String> = []
        var host: String?
    }

    /// The human name a service announcement carries, if any, and how much to trust it
    /// (lower is better). Many announcements are named with machine identifiers instead.
    static func friendlyName(instance: String, type: String, txt: [String: String]) -> (name: String, rank: Int)? {
        func clean(_ s: String) -> String? {
            let v = s.trimmingCharacters(in: .whitespacesAndNewlines)
            let uuid = "^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$"
            let hardwareAddress = "^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"
            if v.isEmpty || v.contains("@") { return nil }
            if v.range(of: uuid, options: .regularExpression) != nil { return nil }
            if v.range(of: hardwareAddress, options: .regularExpression) != nil { return nil }
            return v
        }
        let t = type.lowercased()
        if t.hasPrefix("_apple-mobdev2") || t.hasPrefix("_remotepairing") || t.hasPrefix("_sleep-proxy") { return nil }
        if t.hasPrefix("_raop") {                    // "A851AB0C1D2E@Living Room"
            guard let at = instance.firstIndex(of: "@"),
                  let name = clean(String(instance[instance.index(after: at)...])) else { return nil }
            return (name, 2)
        }
        if t.hasPrefix("_googlecast") {              // the readable name is in the TXT record
            if let fn = txt["fn"], let name = clean(fn) { return (name, 1) }
            let stripped = instance.replacingOccurrences(of: "-[0-9A-Fa-f]{32}$", with: "", options: .regularExpression)
            return clean(stripped).map { ($0, 4) }
        }
        guard let name = clean(instance) else { return nil }
        if t.hasPrefix("_airplay") || t.hasPrefix("_companion-link") || t.hasPrefix("_mediaremotetv") { return (name, 0) }
        if t.hasPrefix("_hap") || t.hasPrefix("_homekit") || t.hasPrefix("_ipp") || t.hasPrefix("_printer")
            || t.hasPrefix("_sonos") || t.hasPrefix("_spotify-connect") { return (name, 3) }
        return (name, 5)
    }

    private let lock = NSLock()
    private struct Record {
        var ips: [String]
        var named: (name: String, rank: Int)?
        var model: String?
        var type: String
        var host: String?
        var order: Int            // position in the sequence of answers, so merging stays first-come
        var removedAt: Date?      // set when the device withdraws the announcement
    }
    /// How long a withdrawn announcement keeps labelling its address. Phones withdraw and
    /// re-announce within seconds, so forgetting at once would make their rows flicker.
    static let linger: TimeInterval = 600
    private var records: [String: Record] = [:]   // one per announcement (name|type), guarded by `lock`
    private var answers = 0
    private var browsers: [String: NetServiceBrowser] = [:]
    private var resolving: [NetService] = []
    private var seen: Set<String> = []

    /// Must be called on the main thread: NetServiceBrowser reports on its run loop.
    /// macOS only lets the app look for the service types listed under NSBonjourServices in its
    /// Info.plist, and refuses the "list every type in use" query outright, so that list is the
    /// complete set: a type missing from it has to be added there (and the app rebuilt).
    func start(types: [String]) {
        for t in types where !t.hasPrefix("_services.") { browse(t) }
    }

    /// Ends every search and forgets what was heard. Main thread only, like start(types:).
    func stop() {
        guard !browsers.isEmpty else { return }
        browsers.values.forEach { $0.stop() }
        browsers.removeAll()
        resolving.forEach { $0.stop() }
        resolving.removeAll()
        seen.removeAll()
        lock.lock()
        records.removeAll()
        lock.unlock()
    }

    private func browse(_ type: String) {
        let key = type.hasSuffix(".") ? type : type + "."
        guard browsers[key] == nil, browsers.count < 90 else { return }
        let b = NetServiceBrowser()
        b.delegate = self
        browsers[key] = b
        b.searchForServices(ofType: key, inDomain: "local.")
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        let key = service.name + "|" + service.type
        guard !seen.contains(key), resolving.count < 300 else { return }
        seen.insert(key)
        service.delegate = self
        resolving.append(service)
        service.resolve(withTimeout: 6)
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didRemove service: NetService, moreComing: Bool) {
        let key = service.name + "|" + service.type
        seen.remove(key)
        lock.lock()
        records[key]?.removedAt = Date()
        lock.unlock()
    }

    /// macOS refused or could not start a search (for example a type missing from NSBonjourServices).
    func netServiceBrowser(_ browser: NetServiceBrowser, didNotSearch errorDict: [String: NSNumber]) {
        let type = browsers.first { $0.value === browser }?.key ?? "?"
        NSLog("SignalScan: Bonjour search for %@ did not start (error %d)", type, errorDict[NetService.errorCode]?.intValue ?? 0)
    }

    /// The key=value attributes of an announcement. Walked by hand: NetService.dictionary(fromTXTRecord:)
    /// aborts the whole app on a key with no "=" (a legal yes/no attribute, RFC 6763 section 6.4).
    /// Such a key reads as "". The first occurrence of a key wins.
    static func attributes(fromTXTRecord data: Data) -> [String: String] {
        var txt: [String: String] = [:]
        let b = [UInt8](data)
        var p = 0
        while p < b.count {
            let s = p + 1, e = s + Int(b[p])
            if e > b.count { break }
            let eq = b[s..<e].firstIndex(of: 0x3D) ?? e
            if eq > s {
                let key = String(decoding: b[s..<eq], as: UTF8.self).lowercased()
                if txt[key] == nil { txt[key] = eq < e ? String(decoding: b[(eq + 1)..<e], as: UTF8.self) : "" }
            }
            p = e
        }
        return txt
    }

    func netServiceDidResolveAddress(_ sender: NetService) {
        var ips: [String] = []
        for data in sender.addresses ?? [] {
            data.withUnsafeBytes { raw in
                guard raw.count >= MemoryLayout<sockaddr_in>.size,
                      let sa = raw.baseAddress?.assumingMemoryBound(to: sockaddr_in.self),
                      sa.pointee.sin_family == sa_family_t(AF_INET) else { return }
                ips.append(ipString(UInt32(bigEndian: sa.pointee.sin_addr.s_addr)))
            }
        }
        let txt = sender.txtRecordData().map(BonjourWatcher.attributes(fromTXTRecord:)) ?? [:]
        let named = BonjourWatcher.friendlyName(instance: sender.name, type: sender.type, txt: txt)
        // AirPlay audio uses "md" for something else ("0,1,2"); its model is under "am".
        let modelKeys = sender.type.lowercased().hasPrefix("_raop") ? ["am"] : ["md", "model"]
        let model = modelKeys.compactMap { txt[$0] }.first { !$0.isEmpty }
        let key = sender.name + "|" + sender.type
        lock.lock()
        if seen.contains(key) {      // an answer for an announcement withdrawn meanwhile is dropped
            answers += 1
            records[key] = Record(ips: ips, named: named, model: model, type: sender.type, host: sender.hostName, order: answers, removedAt: nil)
        }
        lock.unlock()
        finish(sender)
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) { finish(sender) }

    private func finish(_ service: NetService) {
        service.stop()
        resolving.removeAll { $0 === service }
    }

    /// What is announced at each address right now. Built afresh each time, so nothing outlives
    /// its announcement by more than `linger`, and an address that changes hands is relabelled.
    func snapshot(at time: Date = Date()) -> [String: Info] {
        lock.lock()
        records = records.filter { $0.value.removedAt.map { time.timeIntervalSince($0) < BonjourWatcher.linger } ?? true }
        // Current announcements first, then withdrawn ones; within each, in the order they were answered.
        let all = records.values.sorted {
            ($0.removedAt == nil) != ($1.removedAt == nil) ? $0.removedAt == nil : $0.order < $1.order
        }
        lock.unlock()
        var liveHosts: [String: Set<String>] = [:]
        for r in all where r.removedAt == nil { for ip in r.ips { liveHosts[ip, default: []].insert(r.host ?? "") } }
        var byIP: [String: Info] = [:]
        for r in all {
            for ip in r.ips {
                // A withdrawn announcement from a different device than the one announcing here now is stale.
                if r.removedAt != nil, let hosts = liveHosts[ip], !hosts.contains(r.host ?? "") { continue }
                var info = byIP[ip] ?? Info()
                let rank = (r.named?.rank ?? 0) + (r.removedAt == nil ? 0 : 100)   // a current name beats a withdrawn one
                if let n = r.named, rank < info.nameRank { info.name = n.name; info.nameRank = rank }
                if info.model == nil, let m = r.model { info.model = m }
                info.types.insert(r.type)
                if let h = r.host, r.removedAt == nil || info.host == nil { info.host = h }
                byIP[ip] = info
            }
        }
        return byIP
    }
}

func ipString(_ v: UInt32) -> String {
    "\(v >> 24 & 0xFF).\(v >> 16 & 0xFF).\(v >> 8 & 0xFF).\(v & 0xFF)"
}

func ipValue(_ s: String) -> UInt32? {
    let parts = s.split(separator: ".").compactMap { UInt32($0) }
    guard parts.count == 4, parts.allSatisfy({ $0 <= 255 }) else { return nil }
    return parts[0] << 24 | parts[1] << 16 | parts[2] << 8 | parts[3]
}

/// Walks a routing-socket dump of neighbour entries: each record is an rt_msghdr followed by
/// the neighbour's IPv4 address (sockaddr_in) and its hardware address (sockaddr_dl), each
/// padded to four bytes. Entries still being resolved carry no hardware address and are skipped,
/// as are broadcast and multicast addresses. `ifIndex` 0 accepts every interface.
func parseNeighbours(_ buf: [UInt8], count: Int, ifIndex: UInt32) -> [(ip: String, mac: String)] {
    var rows: [(String, String)] = []
    let total = min(count, buf.count)
    let header = MemoryLayout<rt_msghdr>.size
    buf.withUnsafeBytes { raw in
        var offset = 0
        while offset + header <= total {
            let rtm = raw.loadUnaligned(fromByteOffset: offset, as: rt_msghdr.self)
            let length = Int(rtm.rtm_msglen)
            if length < header || offset + length > total { break }
            let end = offset + length
            let sinAt = offset + header
            defer { offset = end }
            guard ifIndex == 0 || UInt32(rtm.rtm_index) == ifIndex,
                  sinAt + MemoryLayout<sockaddr_in>.size <= end else { continue }
            let sin = raw.loadUnaligned(fromByteOffset: sinAt, as: sockaddr_in.self)
            guard sin.sin_family == sa_family_t(AF_INET) else { continue }
            let sinLength = Int(sin.sin_len) > 0 ? (Int(sin.sin_len) + 3) & ~3 : 4
            let sdlAt = sinAt + sinLength                 // sockaddr_dl: name length at +5, address length at +6, data at +8
            guard sdlAt + 8 <= end else { continue }
            let nameLength = Int(raw[sdlAt + 5]), addressLength = Int(raw[sdlAt + 6])
            let macAt = sdlAt + 8 + nameLength
            guard addressLength == 6, macAt + 6 <= end, raw[macAt] & 0x01 == 0 else { continue }
            let mac = (0..<6).map { String(format: "%02X", raw[macAt + $0]) }.joined(separator: ":")
            rows.append((ipString(UInt32(bigEndian: sin.sin_addr.s_addr)), mac))
        }
    }
    return rows
}

/// Finds the devices joined to the same network as this Mac. These are the
/// "Wi-Fi things" (TV, cameras, phones) as opposed to the routers.
final class LANScanner {
    private let queue = DispatchQueue(label: "signalscan.lan", qos: .utility)
    private let bonjour = BonjourWatcher()
    private var rounds = 0
    private var lastSweepAt = 0.0
    private var lastSweep: (sent: Int, failed: Int) = (0, 0)
    private var searchEverywhere = false      // set by `--probe --lan-trusted`, where the caller vouches for the network
    private var answer: Bool?                 // "this is / is not my network" from the dashboard: applied by the scan setTrusted starts, or dropped
    private var bonjourTypes: [String] = []
    private var listening = false             // whether the Bonjour searches are running
    private var lookAgainSoon = false         // names take a few seconds to arrive after the searches start

    /// Networks the user has said are their own, remembered by the router's hardware address.
    /// Only those are searched for devices: sending a packet to every address is fine at home
    /// and unwelcome on an office or public network.
    private static let trustedKey = "trustedRouters"
    private var trustedRouters: Set<String> {
        get { Set(UserDefaults.standard.stringArray(forKey: LANScanner.trustedKey) ?? []) }
        set { UserDefaults.standard.set(newValue.sorted(), forKey: LANScanner.trustedKey) }
    }

    /// The dashboard's "this is my network" / "stop searching this network" buttons end up here.
    func setTrusted(_ yes: Bool) {
        queue.async {
            self.answer = yes
            self.scanOnce()
            self.answer = nil      // an answer is for the network on screen now; never keep it for a later one
            if self.lookAgainSoon {    // the searches have just started: read the names once they are in
                self.lookAgainSoon = false
                self.queue.asyncAfter(deadline: .now() + 4) { [weak self] in self?.scanOnce() }
            }
        }
    }

    // What a Bonjour service type says about the device, most specific first.
    private static let kindHints: [(String, String)] = [
        ("_mediaremotetv._tcp", "Apple TV"),
        ("_airplay._tcp", "AirPlay screen or speaker"),
        ("_googlecast._tcp", "Chromecast / Google TV"),
        ("_androidtvremote2._tcp", "Android TV"),
        ("_amzn-wplay._tcp", "Amazon Fire TV / Echo"),
        ("_nvstream._tcp", "NVIDIA Shield"),
        ("_sonos._tcp", "Sonos speaker"),
        ("_spotify-connect._tcp", "Spotify speaker"),
        ("_raop._tcp", "AirPlay audio"),
        ("_ipp._tcp", "Printer"), ("_ipps._tcp", "Printer"), ("_printer._tcp", "Printer"), ("_pdl-datastream._tcp", "Printer"),
        ("_scanner._tcp", "Scanner"), ("_uscan._tcp", "Scanner"),
        ("_axis-video._tcp", "Camera"), ("_rtsp._tcp", "Camera / video stream"),
        ("_hue._tcp", "Philips Hue bridge"),
        ("_meshcop._udp", "Thread border router"),
        ("_matter._tcp", "Matter smart-home device"), ("_matterc._udp", "Matter smart-home device"),
        ("_hap._tcp", "HomeKit accessory"), ("_homekit._tcp", "HomeKit"),
        ("_esphomelib._tcp", "ESPHome device"), ("_shelly._tcp", "Shelly relay"), ("_miio._udp", "Xiaomi smart device"),
        ("_apple-mobdev2._tcp", "iPhone / iPad"),
        ("_companion-link._tcp", "Apple device"),
        ("_smb._tcp", "File sharing"), ("_afpovertcp._tcp", "File sharing"),
        ("_rfb._tcp", "Screen sharing"), ("_ssh._tcp", "SSH"), ("_sftp-ssh._tcp", "SSH"),
        ("_workstation._tcp", "Computer"),
        ("_http._tcp", "Web interface"),
    ]

    /// `bonjourTypes` overrides the list normally read from the app's Info.plist (used by `--probe`).
    func start(bonjourTypes: [String]? = nil, searchEverywhere: Bool = false) {
        self.searchEverywhere = searchEverywhere
        self.bonjourTypes = bonjourTypes ?? (Bundle.main.infoDictionary?["NSBonjourServices"] as? [String]) ?? []
        queue.async { self.loop() }
    }

    /// Whether the network this Mac is on at this moment is one marked as the user's own.
    /// Reads the route and the neighbour table; sends nothing.
    func trustedNow() -> Bool {
        queue.sync {
            let route = defaultRoute()
            guard let iface = route.iface, let gateway = route.gateway,
                  !["utun", "ipsec", "ppp", "tun", "tap"].contains(where: { iface.hasPrefix($0) }) else { return false }
            guard let mac = arpTable(iface: iface).first(where: { $0.ip == gateway })?.mac else { return false }
            return trustedRouters.contains(mac)
        }
    }

    private func loop() {
        // While the Wi-Fi card is in listening mode this Mac is off its network: keep the last
        // reading on screen and look again once it is back.
        if Store.shared.listening {
            queue.asyncAfter(deadline: .now() + 2) { [weak self] in self?.loop() }
            return
        }
        VendorDB.shared.refresh()   // picks up a vendor list added or replaced while the app is running
        // Like the Wi-Fi scan: look once at launch, then only while a dashboard is being read.
        let wanted = rounds == 0 || Store.shared.watched
        if wanted {
            scanOnce()
            rounds += 1
        } else {
            listen(false)          // nobody is looking: stop asking the network who is there
        }
        let pause: Double = !wanted ? 2 : lookAgainSoon ? 4 : 15
        lookAgainSoon = false
        queue.asyncAfter(deadline: .now() + pause) { [weak self] in self?.loop() }
    }

    /// Device announcements (Bonjour) are only listened for on a network marked as yours, and
    /// only while a dashboard is being read: the searches send questions to the whole network.
    private func listen(_ on: Bool) {
        guard on != listening else { return }
        listening = on
        let types = bonjourTypes
        DispatchQueue.main.async { if on { self.bonjour.start(types: types) } else { self.bonjour.stop() } }
        if on { lookAgainSoon = true }
    }

    private func defaultRoute() -> (gateway: String?, iface: String?) {
        var gateway: String?, iface: String?
        for line in run("/sbin/route", ["-n", "get", "default"]).split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            if parts[0] == "gateway" { gateway = parts[1] }
            if parts[0] == "interface" { iface = parts[1] }
        }
        return (gateway, iface)
    }

    private func address(of ifname: String) -> (ip: UInt32, mask: UInt32)? {
        var ifap: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifap) == 0 else { return nil }
        defer { freeifaddrs(ifap) }
        var p = ifap
        while let cur = p {
            let ifa = cur.pointee
            if String(cString: ifa.ifa_name) == ifname, let addr = ifa.ifa_addr, let mask = ifa.ifa_netmask,
               addr.pointee.sa_family == sa_family_t(AF_INET) {
                let a = addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
                let m = mask.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
                return (UInt32(bigEndian: a), UInt32(bigEndian: m))
            }
            p = ifa.ifa_next
        }
        return nil
    }

    /// Sends one tiny packet to every address on the home network so the Mac
    /// learns which ones answer. Nothing is read from the devices themselves.
    private func sweep(ip: UInt32, mask: UInt32) -> (sent: Int, failed: Int) {
        let net = ip & mask, last = net | ~mask
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return (0, 0) }
        defer { close(fd) }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)
        var sent = 0, failed = 0
        var byte: UInt8 = 0
        var host = net + 1
        while host < last {
            if host != ip {
                var sa = sockaddr_in()
                sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                sa.sin_family = sa_family_t(AF_INET)
                sa.sin_port = UInt16(9).bigEndian
                sa.sin_addr.s_addr = host.bigEndian
                let r = withUnsafePointer(to: &sa) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        sendto(fd, &byte, 1, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                if r < 0 { failed += 1 } else { sent += 1 }
                usleep(2000)
            }
            host += 1
        }
        return (sent, failed)
    }

    /// The kernel's table of IP address to hardware address pairs (what `arp -a` prints).
    /// It has to be read from inside this process: macOS shows it only to the app that holds
    /// Local Network permission, and a helper tool started by the app sees an empty table.
    private func arpTable(iface: String) -> [(ip: String, mac: String)] {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO]
        var needed = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &needed, nil, 0) == 0, needed > 0 else { return [] }
        var size = needed + needed / 8 + 1024          // the table can grow between the two calls
        var buf = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, UInt32(mib.count), &buf, &size, nil, 0) == 0 else { return [] }
        return parseNeighbours(buf, count: size, ifIndex: if_nametoindex(iface))
    }

    private func scanOnce() {
        let route = defaultRoute()
        guard let iface = route.iface, let me = address(of: iface) else {
            listen(false)
            Store.shared.set("lan", ["devices": [], "scanAt": now(), "note": "This Mac is not connected to a network."])
            return
        }
        // A VPN takes over the default route. Its tunnel is not the local network: it has no
        // neighbour table, and a sweep would send packets to the VPN provider's addresses.
        if ["utun", "ipsec", "ppp", "tun", "tap"].contains(where: { iface.hasPrefix($0) }) || me.mask == 0xFFFF_FFFF {
            listen(false)
            Store.shared.set("lan", ["devices": [], "scanAt": now(), "iface": iface,
                "note": "A VPN is on, so Signal Scan cannot list the devices on your own network. Turn the VPN off to see them."])
            return
        }
        // Never sweep more than ~1000 addresses; on a bigger network stay within our own /24.
        let mask = (~me.mask) > 1023 ? 0xFFFF_FF00 : me.mask
        let net = me.ip & mask, last = net | ~mask
        var table = arpTable(iface: iface)
        let routerMAC = table.first { $0.ip == route.gateway }?.mac

        if let yes = answer, let mac = routerMAC {
            var known = trustedRouters
            if yes { known.insert(mac) } else { known.remove(mac) }
            trustedRouters = known
            answer = nil
            lastSweepAt = 0            // act on it straight away
        }
        let trusted = searchEverywhere || (routerMAC.map { trustedRouters.contains($0) } ?? false)

        var section: [String: Any] = [
            "devices": [], "scanAt": now(), "iface": iface, "trusted": trusted,
            "subnet": "\(ipString(net))/\(mask.nonzeroBitCount)",
        ]
        if let g = route.gateway { section["gateway"] = g }

        // Until Local Network access is granted, macOS hides every hardware address from the app:
        // the table comes back empty even though this Mac is certainly talking to its router.
        // Only meaningful when the router is on this Mac's own network.
        let gatewayOnLink = route.gateway.flatMap(ipValue).map { $0 & me.mask == me.ip & me.mask } ?? false
        if gatewayOnLink && table.isEmpty {
            listen(false)
            section["blocked"] = true
            section["note"] = "macOS has not let Signal Scan look at your local network yet, so the device list is empty. Choose Allow on the prompt from Signal Scan, or turn it on under System Settings \u{203A} Privacy & Security \u{203A} Local Network."
            Store.shared.set("lan", section)
            return
        }
        // On a network the user has not marked as theirs, list nothing, ask nothing and probe nothing.
        listen(trusted)
        guard trusted else {
            Store.shared.set("lan", section)
            return
        }
        if now() - lastSweepAt > 45 {
            lastSweep = sweep(ip: me.ip, mask: mask)
            lastSweepAt = now()
            usleep(1_200_000)
            table = arpTable(iface: iface)
        }

        let names = bonjour.snapshot()
        var devices: [[String: Any]] = []
        var seen: Set<String> = []
        for row in table {
            guard let v = ipValue(row.ip), v & mask == net, v != last, v != me.ip, !seen.contains(row.ip) else { continue }
            seen.insert(row.ip)
            var d: [String: Any] = ["ip": row.ip, "mac": row.mac, "private": isPrivateMAC(row.mac)]
            if row.ip == route.gateway { d["gateway"] = true }
            if let vendor = VendorDB.shared.lookup(mac: row.mac) { d["vendor"] = vendor }
            if let info = names[row.ip] {
                if let n = info.name { d["name"] = n }
                if let m = info.model { d["model"] = m }
                if let h = info.host { d["host"] = h.replacingOccurrences(of: ".local.", with: "") }
                var kinds: [String] = []
                for (type, label) in LANScanner.kindHints where info.types.contains(type + ".") && !kinds.contains(label) {
                    kinds.append(label)
                }
                d["kinds"] = Array(kinds.prefix(3))
            }
            devices.append(d)
        }
        var selfRow: [String: Any] = ["ip": ipString(me.ip), "self": true, "name": "This Mac"]
        if let info = names[ipString(me.ip)], let h = info.host { selfRow["host"] = h.replacingOccurrences(of: ".local.", with: "") }
        devices.append(selfRow)
        section["devices"] = devices
        section["scanAt"] = now()
        Store.shared.set("lan", section)
    }
}
