import Foundation
import CoreWLAN

/// Extras a router advertises in its beacon. macOS only hands the raw beacon
/// to apps that hold Location permission, so all of this is optional.
struct IEInfo {
    var secOffset: Int?        // +1 / -1: where a 40 MHz network's second half sits
    var stations: Int?         // devices connected, as the router reports it
    var utilization: Double?   // share of airtime the router sees as busy (0...1)
    var maker: String?
    var model: String?
    var wifi6 = false
    var wifi7 = false
}

func parseIEs(_ data: Data) -> IEInfo {
    var info = IEInfo()
    let b = [UInt8](data)
    var p = 0
    while p + 2 <= b.count {
        let id = b[p], len = Int(b[p + 1])
        let s = p + 2, e = s + len
        if e > b.count { break }
        switch id {
        case 61 where len >= 2:                       // HT Operation
            let off = b[s + 1] & 0x03
            info.secOffset = off == 1 ? 1 : (off == 3 ? -1 : 0)
        case 11 where len >= 3:                       // BSS Load
            info.stations = Int(b[s]) | Int(b[s + 1]) << 8
            info.utilization = Double(b[s + 2]) / 255.0
        case 255 where len >= 1:                      // extension elements
            if b[s] == 35 { info.wifi6 = true }       // HE capabilities
            if b[s] == 108 { info.wifi7 = true }      // EHT capabilities
        case 221 where len >= 4 && b[s] == 0x00 && b[s + 1] == 0x50 && b[s + 2] == 0xF2 && b[s + 3] == 0x04:
            var q = s + 4                             // WPS: type(2) length(2) value
            while q + 4 <= e {
                let type = Int(b[q]) << 8 | Int(b[q + 1])
                let l = Int(b[q + 2]) << 8 | Int(b[q + 3])
                let vs = q + 4, ve = vs + l
                if ve > e { break }
                let text = String(decoding: b[vs..<ve], as: UTF8.self)
                    .trimmingCharacters(in: .whitespacesAndNewlines.union(.controlCharacters))
                if !text.isEmpty {
                    if type == 0x1021 { info.maker = text }
                    if type == 0x1023 { info.model = text }
                }
                q = ve
            }
        default:
            break
        }
        p = e
    }
    return info
}

final class WiFiScanner {
    private let queue = DispatchQueue(label: "signalscan.wifi", qos: .utility)
    private let linkQueue = DispatchQueue(label: "signalscan.link", qos: .utility)
    private var linkTimer: DispatchSourceTimer?
    private var cache: [String: [String: Any]] = [:]   // by BSSID, when macOS lets us see them
    private var scans = 0
    private var heardAt = 0.0   // when a scan last really listened to the air

    func start() {
        queue.async { self.loop() }
        // The link this Mac is on can be read every second without a scan, so the dashboard
        // can follow it live while the laptop is carried around. Other routers only refresh
        // when a full scan completes.
        let timer = DispatchSource.makeTimerSource(queue: linkQueue)
        timer.schedule(deadline: .now() + 0.5, repeating: 1.0, leeway: .milliseconds(100))
        timer.setEventHandler { [weak self] in self?.sampleLink() }
        timer.resume()
        linkTimer = timer
    }

    private func sampleLink() {
        guard !Store.shared.listening, let i = CWWiFiClient.shared().interface() else { return }
        var link = readInterface(i)
        link["at"] = now()
        Store.shared.set("link", link)
    }

    private func loop() {
        // A full scan takes the radio off this Mac's own channel for about 5 s and slows its
        // connection meanwhile, so scan once at launch and after that only while a dashboard
        // is being read. While idle, look again every second so an opened page fills quickly.
        let wanted = (scans == 0 || Store.shared.watched) && !Store.shared.listening
        if wanted { scanOnce() }
        queue.asyncAfter(deadline: .now() + (wanted ? 5.0 : 1.0)) { [weak self] in self?.loop() }
    }

    private func describe(_ ch: CWChannel?) -> [String: Any] {
        guard let ch = ch else { return [:] }
        let band = [1: 2, 2: 5, 3: 6][ch.channelBand.rawValue] ?? 0
        let width = [1: 20, 2: 40, 3: 80, 4: 160][ch.channelWidth.rawValue] ?? 20
        guard band != 0 else { return [:] }
        return ["channel": ch.channelNumber, "band": band, "width": width]
    }

    private static let securityNames: [(CWSecurity, String)] = [
        (.wpa3Personal, "WPA3"), (.wpa3Transition, "WPA2/WPA3"), (.wpa2Personal, "WPA2"),
        (.wpaPersonalMixed, "WPA/WPA2"), (.wpaPersonal, "WPA"),
        (.wpa3Enterprise, "WPA3 Enterprise"), (.wpa2Enterprise, "WPA2 Enterprise"),
        (.wpaEnterpriseMixed, "WPA/WPA2 Enterprise"), (.wpaEnterprise, "WPA Enterprise"),
        (.dynamicWEP, "WEP"), (.WEP, "WEP"),
    ]

    private func security(of n: CWNetwork) -> String {
        for (mode, name) in WiFiScanner.securityNames where n.supportsSecurity(mode) { return name }
        if let owe = CWSecurity(rawValue: 14), n.supportsSecurity(owe) { return "Enhanced Open" }
        if n.supportsSecurity(.none) { return "Open (no password)" }
        return ""
    }

    private func securityName(raw: Int) -> String {
        if raw == 0 { return "Open (no password)" }
        if raw == 14 || raw == 15 { return "Enhanced Open" }
        for (mode, name) in WiFiScanner.securityNames where mode.rawValue == raw { return name }
        return ""
    }

    private func phy(of n: CWNetwork, _ ie: IEInfo?) -> String {
        if ie?.wifi7 == true { return "be" }
        if n.supportsPHYMode(.mode11ax) { return "ax" }
        if n.supportsPHYMode(.mode11ac) { return "ac" }
        if n.supportsPHYMode(.mode11n) { return "n" }
        if n.supportsPHYMode(.mode11g) { return "g" }
        if n.supportsPHYMode(.mode11a) { return "a" }
        if n.supportsPHYMode(.mode11b) { return "b" }
        return ""
    }

    private func readInterface(_ i: CWInterface) -> [String: Any] {
        var iface: [String: Any] = ["name": i.interfaceName ?? "", "power": i.powerOn()]
        if let s = i.ssid() { iface["ssid"] = s }
        if let b = i.bssid() { iface["bssid"] = b.uppercased() }
        if let cc = i.countryCode() { iface["country"] = cc }
        let ch = describe(i.wlanChannel())
        let associated = !ch.isEmpty && i.rssiValue() != 0
        iface["associated"] = associated
        if associated {
            iface.merge(ch) { a, _ in a }
            iface["rssi"] = i.rssiValue()
            if i.noiseMeasurement() != 0 { iface["noise"] = i.noiseMeasurement() }
            iface["txRate"] = i.transmitRate()
            iface["phy"] = [1: "a", 2: "b", 3: "g", 4: "n", 5: "ac", 6: "ax"][i.activePHYMode().rawValue] ?? ""
            iface["security"] = securityName(raw: i.security().rawValue)
        }
        return iface
    }

    private func scanOnce() {
        let started = now()
        guard let i = CWWiFiClient.shared().interface() else {
            Store.shared.set("wifi", ["error": "No Wi-Fi interface found on this Mac.", "networks": [], "iface": [:], "scanAt": started])
            return
        }
        guard i.powerOn() else {
            Store.shared.set("wifi", ["error": "Wi-Fi is turned off.", "networks": [], "iface": readInterface(i), "scanAt": started])
            return
        }
        var list: [[String: Any]] = []
        var redacted = false
        var failure: String?
        do {
            let nets = try i.scanForNetworks(withName: nil, includeHidden: true)
            let t = now()
            // macOS answers every other request from its own cache in well under a second without
            // listening again (measured: 0.04-0.5 s, against 4-5 s for a real scan). Only a scan
            // that took real time may refresh the timestamps.
            let fresh = heardAt == 0 || t - started > 1.0
            if fresh { heardAt = t }
            // Without Location permission macOS strips every name and address.
            redacted = !nets.isEmpty && nets.allSatisfy { $0.bssid == nil }
            for n in nets {
                var e = describe(n.wlanChannel)
                guard !e.isEmpty, n.rssiValue < 0 else { continue }
                e["rssi"] = n.rssiValue
                if n.noiseMeasurement != 0 { e["noise"] = n.noiseMeasurement }
                if let s = n.ssid, !s.isEmpty { e["ssid"] = s } else if !redacted { e["hidden"] = true }
                var ie: IEInfo?
                if let d = n.informationElementData { ie = parseIEs(d) }
                if let ie = ie {
                    if let v = ie.secOffset { e["secOffset"] = v }
                    if let v = ie.stations { e["stations"] = v }
                    if let v = ie.utilization { e["utilization"] = v }
                    if let v = ie.maker { e["maker"] = v }
                    if let v = ie.model { e["model"] = v }
                }
                e["security"] = security(of: n)
                e["phy"] = phy(of: n, ie)
                e["lastSeen"] = fresh ? t : ((n.bssid.flatMap { cache[$0.uppercased()]?["lastSeen"] as? Double }) ?? heardAt)
                if let b = n.bssid?.uppercased() {
                    e["bssid"] = b
                    e["id"] = b
                    if let v = VendorDB.shared.lookup(mac: b) { e["vendor"] = v }
                    // A router only states its make and model in some broadcasts: keep what an earlier scan heard.
                    if let earlier = cache[b] {
                        for key in ["maker", "model"] where e[key] == nil {
                            if let kept = earlier[key] { e[key] = kept }
                        }
                    }
                    cache[b] = e
                } else {
                    list.append(e)
                }
            }
            if !redacted {
                // A single scan misses a few routers; keep each for 40 s after it was last heard.
                // Only a scan that really listened may drop one: an answer from macOS's cache is
                // no news, and after a pause every timestamp is old.
                if fresh { cache = cache.filter { t - (($0.value["lastSeen"] as? Double) ?? 0) < 40 } }
                list = Array(cache.values)
            } else {
                cache.removeAll()
                list.sort {
                    let a = (($0["band"] as? Int) ?? 0, ($0["channel"] as? Int) ?? 0, -(($0["rssi"] as? Int) ?? 0))
                    let b = (($1["band"] as? Int) ?? 0, ($1["channel"] as? Int) ?? 0, -(($1["rssi"] as? Int) ?? 0))
                    return a < b
                }
                for idx in list.indices { list[idx]["id"] = "anon-\(idx)" }
            }
        } catch {
            failure = "The last Wi-Fi scan failed: \(error.localizedDescription)"
            list = Array(cache.values)
        }
        // Which router this Mac is on is decided now, from the same reading that is published as
        // "iface". Kept inside the cache, the flag outlived a switch to another router.
        let iface = readInterface(i)
        if let live = iface["bssid"] as? String {
            for idx in list.indices where (list[idx]["bssid"] as? String) == live { list[idx]["current"] = true }
        }
        scans += 1
        var section: [String: Any] = [
            "iface": iface, "networks": list, "redacted": redacted,
            "scanAt": heardAt > 0 ? heardAt : now(), "took": now() - started, "scans": scans,
        ]
        if let failure = failure { section["error"] = failure }
        Store.shared.set("wifi", section)
    }
}
