import Foundation
import CoreBluetooth

/// One Apple "Continuity" message inside an advertisement: its declared length and first bytes.
struct AppleMessage {
    let length: Int
    let head: [UInt8]
}

/// What a device's advertisements say about it.
struct BLEKind {
    var vendor: String?
    var kind: String?
    /// A broad group the page sorts by: tracker, audio, personal, media, input, health, home or beacon.
    var group: String?
    /// Only for trackers that say so: true once it has been away from its owner for a while.
    var away: Bool?
}

/// Splits manufacturer data into the maker code and, for Apple, its Continuity messages
/// (type, length, payload, repeated). Only the first four payload bytes of each are kept.
func readManufacturerData(_ bytes: [UInt8]) -> (company: Int?, apple: [UInt8: AppleMessage]) {
    if bytes.count < 2 { return (nil, [:]) }
    let company = Int(bytes[0]) | Int(bytes[1]) << 8
    var apple: [UInt8: AppleMessage] = [:]
    if company != 0x004C { return (company, apple) }
    var p = 2
    while p + 1 < bytes.count {
        let length = Int(bytes[p + 1])
        let start = p + 2
        let end = min(bytes.count, start + min(length, 4))
        let head: [UInt8] = start < end ? Array(bytes[start..<end]) : []
        apple[bytes[p]] = AppleMessage(length: length, head: head)
        p = start + length
    }
    return (company, apple)
}

/// Names the kind of device behind an advertisement. The tracker formats follow AirGuard
/// (github.com/seemoo-lab/AirGuard), the open-source tracker detector from TU Darmstadt.
enum BLEClassifier {
    // Bluetooth SIG company identifiers (the maker code inside an advertisement).
    static let companies: [Int: String] = [
        0x004C: "Apple", 0x0006: "Microsoft", 0x0075: "Samsung", 0x00E0: "Google", 0x0171: "Amazon",
        0x0087: "Garmin", 0x009E: "Bose", 0x012D: "Sony", 0x00C4: "LG", 0x038F: "Xiaomi", 0x027D: "Huawei",
        0x0059: "Nordic Semiconductor", 0x000D: "Texas Instruments", 0x000F: "Broadcom", 0x0002: "Intel",
        0x02E5: "Espressif", 0x0499: "Ruuvi", 0x0065: "HP",
        0x06D0: "VeSync (Levoit, Cosori, Etekcity)",
    ]

    // Apple "Continuity" message types, most telling first. Find My (0x12) is read separately.
    static let appleKinds: [(UInt8, String, String)] = [
        (0x07, "AirPods or Beats", "audio"),
        (0x02, "iBeacon (a beacon of any make)", "beacon"),
        (0x09, "AirPlay receiver (Apple TV, HomePod, TV)", "media"),
        (0x06, "HomeKit accessory", "home"),
        (0x0A, "AirPlay source", "personal"),
        (0x10, "iPhone, iPad, Mac, Watch, Apple TV or HomePod", "personal"),
        (0x0C, "Apple device (Handoff)", "personal"),
        (0x0F, "Apple device", "personal"),
        (0x05, "Apple device (AirDrop)", "personal"),
    ]

    // Trackers that announce themselves by a service identifier but say nothing about their owner.
    static let trackerServices: [(String, String, String)] = [
        ("FEED", "Tile tracker", "Tile"), ("FEEC", "Tile tracker", "Tile"),
        ("FE33", "Chipolo tracker", "Chipolo"), ("FA25", "Pebblebee tracker", "Pebblebee"),
    ]

    // Other 16-bit service identifiers that give a device away: identifier, label, maker, group.
    static let serviceKinds: [(String, String, String?, String)] = [
        // Google owns these two protocols; the device itself can be any make, so name no maker.
        ("FEAA", "Eddystone beacon", nil, "beacon"),
        ("FE2C", "Fast Pair accessory (usually earbuds or a speaker)", nil, "audio"),
        ("FD6F", "Exposure-notification beacon", nil, "beacon"),
        ("FD69", "Samsung phone or tablet", "Samsung", "personal"),
        ("FE95", "Xiaomi smart device", "Xiaomi", "home"),
        ("FE07", "Sonos speaker", "Sonos", "audio"),
        ("FEBE", "Bose audio", "Bose", "audio"),
        ("FE03", "Amazon device", "Amazon", "home"),
        ("184E", "LE Audio earbuds or speaker", nil, "audio"),
        ("1853", "LE Audio earbuds or speaker", nil, "audio"),
        ("1812", "Keyboard, mouse or remote", nil, "input"),
        ("180D", "Heart-rate sensor", nil, "health"),
        ("1816", "Bike speed or cadence sensor", nil, "health"),
        ("1818", "Bike power meter", nil, "health"),
        ("1814", "Running sensor", nil, "health"),
        ("1826", "Fitness machine", nil, "health"),
        ("181D", "Weighing scale", nil, "health"),
        ("1810", "Blood-pressure monitor", nil, "health"),
        ("1808", "Glucose meter", nil, "health"),
        ("1809", "Thermometer", nil, "health"),
        ("1822", "Pulse oximeter", nil, "health"),
        ("181A", "Temperature or air sensor", nil, "home"),
    ]

    static func describe(company: Int?, apple: [UInt8: AppleMessage], services: Set<String>, serviceData: [String: [UInt8]]) -> BLEKind {
        var r = BLEKind()
        if let id = company { r.vendor = companies[id] }
        name(&r, company: company, apple: apple, services: services, serviceData: serviceData)
        // Identifiers are handed out in order (highest today: 0x114C). Anything far above that is
        // payload from a device that ignores the format, not a maker, so say nothing rather than guess.
        if r.vendor == nil, r.group != "beacon", let id = company, id < 0x2000 { r.vendor = String(format: "Maker code 0x%04X", id) }
        return r
    }

    private static func name(_ r: inout BLEKind, company: Int?, apple: [UInt8: AppleMessage], services: Set<String>, serviceData: [String: [UInt8]]) {
        // Trackers first: whether something is travelling with you matters more than anything else here.
        if let message = apple[0x12] { findMy(message, into: &r); return }
        if let data = serviceData["FD5A"] { smartTag(data, into: &r); return }
        if let frame = serviceData["FEAA"]?.first, frame == 0x40 || frame == 0x41 {
            // Google's Find Hub network: the last bit is set once the owner has been away for hours.
            r.kind = frame == 0x41 ? "Find Hub tag or phone, away from its owner" : "Find Hub tag or phone"
            r.group = "tracker"
            r.away = frame == 0x41
            return
        }
        for (uuid, label, maker) in trackerServices where services.contains(uuid) {
            r.kind = label
            r.group = "tracker"
            if r.vendor == nil { r.vendor = maker }
            return
        }
        if company == 0x004C {
            for (type, label, group) in appleKinds where apple[type] != nil {
                r.kind = label
                r.group = group
                break
            }
            if r.kind == nil { r.kind = "Apple device"; r.group = "personal" }
            // Every iBeacon carries Apple's maker code whoever built it, so it says nothing about the maker.
            if r.group == "beacon" { r.vendor = nil }
            return
        }
        for (uuid, label, maker, group) in serviceKinds where services.contains(uuid) {
            r.kind = label
            r.group = group
            if r.vendor == nil { r.vendor = maker }
            return
        }
        if company == 0x0006 { r.kind = "Windows PC or Microsoft accessory"; r.group = "personal" }
        if company == 0x0087 { r.kind = "Garmin watch or sensor"; r.group = "personal" }
    }

    /// Apple's Find My network. The status byte says what sent the message, and the full
    /// 25-byte key is only sent once the device has been away from its owner for a while.
    private static func findMy(_ m: AppleMessage, into r: inout BLEKind) {
        let status: UInt8 = m.head.first ?? 0
        let away = m.length == 0x19
        switch (status & 0x30) >> 4 {
        case 1:
            r.kind = away ? "AirTag, away from its owner" : "AirTag"
            r.group = "tracker"
            r.away = away
        case 2:
            // Another maker's tag on Apple's network (and some newer AirTags).
            r.kind = away ? "Find My tracker, away from its owner" : "Find My tracker"
            r.group = "tracker"
            r.away = away
        case 3:
            r.kind = away ? "AirPods, away from their owner" : "AirPods"
            r.group = "audio"
            r.away = away
        default:
            r.kind = away ? "Apple device, findable while offline" : "Apple device on Find My"
            r.group = "personal"
        }
    }

    /// Samsung SmartTag: the low three bits of its first byte give its state.
    private static func smartTag(_ data: [UInt8], into r: inout BLEKind) {
        r.vendor = "Samsung"
        guard let first = data.first, (first & 0xF8) == 0x10 else {
            r.kind = "Samsung device (SmartThings Find)"
            return
        }
        let state = first & 0x07
        let away = state == 0x02 || state == 0x03   // offline, or offline for a long time
        r.kind = away ? "Samsung SmartTag, away from its owner" : "Samsung SmartTag"
        r.group = "tracker"
        r.away = away
    }
}

/// Listens for Bluetooth Low Energy advertisements. Every nearby device that
/// announces itself shows up here with the strength this Mac hears it at.
final class BLEScanner: NSObject, CBCentralManagerDelegate {
    private struct Dev {
        var name: String?
        var rssi: Double
        var companyId: Int?
        var apple: [UInt8: AppleMessage] = [:]
        var services: Set<String> = []
        var serviceData: [String: [UInt8]] = [:]
        var connectable = false
        var lastSeen: Double
        var adverts = 0
    }

    private let queue = DispatchQueue(label: "signalscan.ble", qos: .utility)
    private var central: CBCentralManager?
    private var devices: [UUID: Dev] = [:]
    private var timer: DispatchSourceTimer?
    private var scanning = false

    func start() {
        central = CBCentralManager(delegate: self, queue: queue, options: [CBCentralManagerOptionShowPowerAlertKey: false])
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 1, repeating: 1.0)
        t.setEventHandler { [weak self] in self?.publish() }
        t.resume()
        timer = t
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        scanning = false
        publish()
    }

    /// Listen only while a dashboard is being read: scanning costs battery and shares the
    /// Mac's 2.4 GHz radio time with its own Wi-Fi.
    private func followTheAudience() {
        guard let central = central, central.state == .poweredOn else { scanning = false; return }
        let wanted = Store.shared.watched
        if wanted && !scanning {
            central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
            scanning = true
        } else if !wanted && scanning {
            central.stopScan()
            scanning = false
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData ad: [String: Any], rssi RSSI: NSNumber) {
        let r = RSSI.doubleValue
        guard r < 0, r > -120 else { return }     // 127 means "no reading"
        let t = now()
        var d = devices[peripheral.identifier] ?? Dev(rssi: r, lastSeen: t)
        d.rssi = d.adverts == 0 ? r : d.rssi * 0.7 + r * 0.3
        d.lastSeen = t
        d.adverts += 1
        if let n = (ad[CBAdvertisementDataLocalNameKey] as? String) ?? peripheral.name, !n.isEmpty { d.name = n }
        if let m = ad[CBAdvertisementDataManufacturerDataKey] as? Data {
            let parsed = readManufacturerData([UInt8](m))
            if let company = parsed.company { d.companyId = company }
            // A device takes turns with its messages: keep each type, the newest copy of it.
            for (type, message) in parsed.apple { d.apple[type] = message }
        }
        if let uuids = ad[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] {
            for u in uuids { d.services.insert(u.uuidString.uppercased()) }
        }
        if let data = ad[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data] {
            for (u, value) in data {
                let key = u.uuidString.uppercased()
                d.services.insert(key)
                d.serviceData[key] = Array([UInt8](value).prefix(4))
            }
        }
        if let c = ad[CBAdvertisementDataIsConnectable] as? NSNumber { d.connectable = c.boolValue }
        devices[peripheral.identifier] = d
    }

    private func publish() {
        followTheAudience()
        let t = now()
        devices = devices.filter { t - $0.value.lastSeen < 60 }   // gone quiet for a minute: drop it
        var list: [[String: Any]] = []
        for (id, d) in devices {
            var e: [String: Any] = ["id": id.uuidString, "rssi": Int(d.rssi.rounded()), "connectable": d.connectable]
            if let n = d.name { e["name"] = n }
            let c = BLEClassifier.describe(company: d.companyId, apple: d.apple, services: d.services, serviceData: d.serviceData)
            if let v = c.vendor { e["vendor"] = v }
            if let k = c.kind { e["kind"] = k }
            if let g = c.group { e["group"] = g }
            if let a = c.away { e["away"] = a }
            // The raw codes travel with the reading, so a label can be corrected on the page
            // later without rebuilding the app.
            if let company = d.companyId { e["company"] = company }
            if !d.apple.isEmpty { e["appleTypes"] = d.apple.keys.map { Int($0) }.sorted() }
            if let fm = d.apple[0x12] { e["findMy"] = [fm.length, Int(fm.head.first ?? 0)] }
            if !d.services.isEmpty { e["services"] = Array(d.services.sorted().prefix(8)) }
            list.append(e)
        }
        let state: String
        switch central?.state ?? .unknown {
        case .poweredOn: state = "on"
        case .poweredOff: state = "off"
        case .unauthorized: state = "unauthorized"
        case .unsupported: state = "unsupported"
        case .resetting: state = "resetting"
        default: state = "starting"
        }
        let permission: String
        switch CBCentralManager.authorization {
        case .allowedAlways: permission = "allowed"
        case .denied: permission = "denied"
        case .restricted: permission = "restricted"
        default: permission = "notDetermined"
        }
        Store.shared.set("ble", ["state": state, "permission": permission, "devices": list, "at": t])
    }
}
