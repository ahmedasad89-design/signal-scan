import Foundation
import CoreBluetooth

/// Listens for Bluetooth Low Energy advertisements. Every nearby device that
/// announces itself shows up here with the strength this Mac hears it at.
final class BLEScanner: NSObject, CBCentralManagerDelegate {
    private struct Dev {
        var name: String?
        var rssi: Double
        var companyId: Int?
        var appleTypes: Set<UInt8> = []
        var services: Set<String> = []
        var connectable = false
        var lastSeen: Double
        var adverts = 0
    }

    private let queue = DispatchQueue(label: "signalscan.ble", qos: .utility)
    private var central: CBCentralManager?
    private var devices: [UUID: Dev] = [:]
    private var timer: DispatchSourceTimer?
    private var scanning = false

    // Bluetooth SIG company identifiers (the maker code inside an advertisement).
    private static let companies: [Int: String] = [
        0x004C: "Apple", 0x0006: "Microsoft", 0x0075: "Samsung", 0x00E0: "Google", 0x0171: "Amazon",
        0x0087: "Garmin", 0x009E: "Bose", 0x012D: "Sony", 0x00C4: "LG", 0x038F: "Xiaomi", 0x027D: "Huawei",
        0x0059: "Nordic Semiconductor", 0x000D: "Texas Instruments", 0x000F: "Broadcom", 0x0002: "Intel",
        0x02E5: "Espressif", 0x0499: "Ruuvi", 0x0065: "HP",
        0x06D0: "VeSync (Levoit, Cosori, Etekcity)",
    ]

    // Apple "Continuity" message types, most telling first.
    private static let appleKinds: [(UInt8, String)] = [
        (0x07, "AirPods or Beats"),
        (0x12, "Find My beacon (AirTag or a findable Apple device)"),
        (0x02, "iBeacon"),
        (0x09, "AirPlay receiver (Apple TV, HomePod, TV)"),
        (0x0A, "AirPlay source"),
        (0x10, "iPhone, iPad, Mac, Watch, Apple TV or HomePod"),
        (0x0C, "Apple device (Handoff)"),
        (0x0F, "Apple device"),
        (0x05, "Apple device (AirDrop)"),
    ]

    // 16-bit service identifiers that give a device away.
    private static let serviceKinds: [(String, String, String?)] = [
        // Google owns these two protocols; the device itself can be any make, so name no maker.
        ("FEAA", "Eddystone beacon", nil),
        ("FE2C", "Fast Pair accessory", nil),
        ("FD6F", "Exposure-notification beacon", nil),
        ("FEED", "Tile tracker", "Tile"), ("FEEC", "Tile tracker", "Tile"),
        ("FE95", "Xiaomi smart device", "Xiaomi"),
        ("FE07", "Sonos speaker", "Sonos"),
        ("FEBE", "Bose audio", "Bose"),
        ("FE03", "Amazon device", "Amazon"),
        ("1812", "Keyboard, mouse or remote", nil),
        ("180D", "Heart-rate sensor", nil),
    ]

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
        if let m = ad[CBAdvertisementDataManufacturerDataKey] as? Data, m.count >= 2 {
            let bytes = [UInt8](m)
            let id = Int(bytes[0]) | Int(bytes[1]) << 8
            d.companyId = id
            if id == 0x004C {
                var p = 2
                while p + 1 < bytes.count {
                    d.appleTypes.insert(bytes[p])
                    p += 2 + Int(bytes[p + 1])
                }
            }
        }
        if let uuids = ad[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] {
            for u in uuids { d.services.insert(u.uuidString.uppercased()) }
        }
        if let data = ad[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data] {
            for u in data.keys { d.services.insert(u.uuidString.uppercased()) }
        }
        if let c = ad[CBAdvertisementDataIsConnectable] as? NSNumber { d.connectable = c.boolValue }
        devices[peripheral.identifier] = d
    }

    private func classify(_ d: Dev) -> (vendor: String?, kind: String?) {
        var vendor = d.companyId.flatMap { BLEScanner.companies[$0] }
        var kind: String?
        if d.companyId == 0x004C {
            kind = BLEScanner.appleKinds.first { d.appleTypes.contains($0.0) }?.1 ?? "Apple device"
        }
        // Every iBeacon carries Apple's maker code whoever built it, so it says nothing about the maker.
        if kind == "iBeacon" { return (nil, "iBeacon (a beacon of any make)") }
        if kind == nil {
            for (uuid, label, maker) in BLEScanner.serviceKinds where d.services.contains(uuid) {
                kind = label
                if vendor == nil { vendor = maker }
                break
            }
        }
        if kind == nil, d.companyId == 0x0006 { kind = "Windows PC or Microsoft accessory" }
        // Identifiers are handed out in order (highest today: 0x114C). Anything far above that is
        // payload from a device that ignores the format, not a maker, so say nothing rather than guess.
        if vendor == nil, let id = d.companyId, id < 0x2000 { vendor = String(format: "Maker code 0x%04X", id) }
        return (vendor, kind)
    }

    private func publish() {
        followTheAudience()
        let t = now()
        devices = devices.filter { t - $0.value.lastSeen < 60 }   // gone quiet for a minute: drop it
        var list: [[String: Any]] = []
        for (id, d) in devices {
            var e: [String: Any] = ["id": id.uuidString, "rssi": Int(d.rssi.rounded()), "connectable": d.connectable]
            if let n = d.name { e["name"] = n }
            let c = classify(d)
            if let v = c.vendor { e["vendor"] = v }
            if let k = c.kind { e["kind"] = k }
            // The raw codes travel with the reading, so a label can be corrected on the page
            // later without rebuilding the app.
            if let company = d.companyId { e["company"] = company }
            if !d.appleTypes.isEmpty { e["appleTypes"] = d.appleTypes.map { Int($0) }.sorted() }
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
