import Foundation

/// Latest reading from each scanner, ready to serialise for the dashboard.
final class Store {
    static let shared = Store()
    private let lock = NSLock()
    private var sections: [String: Any] = [:]

    func set(_ key: String, _ value: Any) {
        lock.lock()
        sections[key] = value
        lock.unlock()
    }

    func get(_ key: String) -> Any? {
        lock.lock()
        defer { lock.unlock() }
        return sections[key]
    }

    private var paused = false

    /// True while the Wi-Fi card is in listening mode (see Air.swift). The ordinary Wi-Fi scan
    /// and the network search stand down meanwhile: both would pull the card off the channel
    /// being heard, and the Mac is off its network anyway.
    var listening: Bool {
        get { lock.lock(); defer { lock.unlock() }; return paused }
        set { lock.lock(); paused = newValue; lock.unlock() }
    }

    private var lastRead = 0.0

    /// True while a dashboard has asked for the readings in the last 10 seconds. A page that is
    /// on screen asks once a second; a hidden or closed one does not ask at all. The scanners
    /// use this to go quiet when nobody is looking.
    var watched: Bool {
        lock.lock()
        defer { lock.unlock() }
        return abs(now() - lastRead) < 10
    }

    func snapshotJSON() -> Data {
        lock.lock()
        lastRead = now()
        var out = sections
        lock.unlock()
        out["now"] = now()
        return (try? JSONSerialization.data(withJSONObject: out, options: [])) ?? Data("{}".utf8)
    }
}

func now() -> Double { Date().timeIntervalSince1970 }

/// Runs a system tool and returns its stdout ("" on failure).
func run(_ path: String, _ args: [String]) -> String {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: path)
    p.arguments = args
    let pipe = Pipe()
    p.standardOutput = pipe
    p.standardError = FileHandle.nullDevice
    do { try p.run() } catch { return "" }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return String(decoding: data, as: UTF8.self)
}

/// Splits one CSV line into at most `limit` leading fields, honouring quotes.
func csvFields(_ line: String, limit: Int) -> [String] {
    var fields: [String] = []
    var cur = ""
    var inQuotes = false
    let chars = Array(line)
    var i = 0
    while i < chars.count {
        let c = chars[i]
        if inQuotes {
            if c == "\"" {
                if i + 1 < chars.count, chars[i + 1] == "\"" { cur.append("\""); i += 1 } else { inQuotes = false }
            } else {
                cur.append(c)
            }
        } else if c == "\"" {
            inQuotes = true
        } else if c == "," {
            fields.append(cur)
            cur = ""
            if fields.count == limit { return fields }
        } else {
            cur.append(c)
        }
        i += 1
    }
    fields.append(cur)
    return fields
}

/// Maker lookup from the first three bytes of a hardware address.
/// Optional: reads the IEEE `oui.csv` registry if one has been placed in
/// ~/Library/Application Support/SignalScan/ (or the app's Resources).
final class VendorDB {
    static let shared = VendorDB()
    private let lock = NSLock()
    private let work = DispatchQueue(label: "signalscan.vendors", qos: .utility)
    private var map: [String: String] = [:]
    private var loadedFrom: String?
    private var loadedStamp: Date?

    /// Loads the list in the background, or reloads it if the file has been added or
    /// replaced since the last call. Cheap to call often.
    func refresh() {
        work.async { self.refreshNow() }
    }

    private func refreshNow() {
        var candidates: [String] = []
        if let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
            candidates.append(support.appendingPathComponent("SignalScan/oui.csv").path)
        }
        if let res = Bundle.main.resourcePath { candidates.append(res + "/oui.csv") }
        for path in candidates {
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: path),
                  let stamp = attrs[.modificationDate] as? Date else { continue }
            lock.lock()
            let unchanged = loadedFrom == path && loadedStamp == stamp
            lock.unlock()
            if unchanged { return }
            guard let data = FileManager.default.contents(atPath: path) else { continue }
            let parsed = VendorDB.parse(String(decoding: data, as: UTF8.self))
            guard !parsed.isEmpty else { continue }
            lock.lock()
            map = parsed
            loadedFrom = path
            loadedStamp = stamp
            lock.unlock()
            Store.shared.set("vendors", parsed.count)
            return
        }
        lock.lock()
        let nothingLoaded = map.isEmpty
        lock.unlock()
        if nothingLoaded { Store.shared.set("vendors", 0) }
    }

    static func parse(_ text: String) -> [String: String] {
        var out: [String: String] = [:]
        text.enumerateLines { line, _ in
            let f = csvFields(line, limit: 3)
            guard f.count >= 3 else { return }
            let hex = f[1].uppercased()
            guard hex.count == 6, hex.allSatisfy({ $0.isHexDigit }) else { return }
            let name = f[2].trimmingCharacters(in: .whitespaces)
            // Two registry entries are placeholders, not makers: blocks the IEEE has split up
            // among many small companies, and owners who asked not to be named. Naming a
            // device after either would be wrong, so those prefixes stay unknown.
            if name.isEmpty || name == "Private" || name == "IEEE Registration Authority" { return }
            out[hex] = name
        }
        return out
    }

    func lookup(mac: String) -> String? {
        let hex = mac.replacingOccurrences(of: ":", with: "").uppercased()
        guard hex.count >= 6 else { return nil }
        lock.lock()
        defer { lock.unlock() }
        return map[String(hex.prefix(6))]
    }
}

/// True for the randomised ("private") addresses phones and laptops use on Wi-Fi.
func isPrivateMAC(_ mac: String) -> Bool {
    guard mac.count >= 2, let first = UInt8(mac.prefix(2), radix: 16) else { return false }
    return first & 0x02 != 0
}
