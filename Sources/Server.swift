import Foundation
import Network

/// Serves the dashboard and the live readings to this Mac only (127.0.0.1).
final class HTTPServer {
    /// Serve dashboard.html from this folder instead of the app bundle, so the
    /// page can be edited without rebuilding the app.
    var webRoot: String?

    /// Runs a command from one of the dashboard's buttons (a POST to the given path).
    /// Returns false if the path is not a command.
    var onCommand: ((String) -> Bool)?

    private var listener: NWListener?
    private let queue = DispatchQueue(label: "signalscan.http")
    private var port: UInt16 = 0

    func start(onReady: @escaping (UInt16) -> Void) {
        queue.async { self.tryStart(8377, onReady) }
    }

    private func tryStart(_ candidate: UInt16, _ onReady: @escaping (UInt16) -> Void) {
        guard candidate < 8387, let nwPort = NWEndpoint.Port(rawValue: candidate) else {
            NSLog("SignalScan: no free port between 8377 and 8386")
            return
        }
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: nwPort)
        guard let l = try? NWListener(using: params) else {
            tryStart(candidate + 1, onReady)
            return
        }
        l.newConnectionHandler = { [weak self] c in self?.accept(c) }
        l.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.port = candidate
                onReady(candidate)
            case .failed:
                l.cancel()
                self?.queue.async { self?.tryStart(candidate + 1, onReady) }
            default:
                break
            }
        }
        listener = l
        l.start(queue: queue)
    }

    private func accept(_ c: NWConnection) {
        c.start(queue: queue)
        read(c, Data())
    }

    private func read(_ c: NWConnection, _ soFar: Data) {
        c.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, done, error in
            guard let self = self else { c.cancel(); return }
            var buf = soFar
            if let data = data { buf.append(data) }
            if let end = buf.range(of: Data([13, 10, 13, 10])) {
                self.respond(c, String(decoding: buf.subdata(in: buf.startIndex..<end.lowerBound), as: UTF8.self))
            } else if done || error != nil || buf.count > 32768 {
                c.cancel()
            } else {
                self.read(c, buf)
            }
        }
    }

    private func respond(_ c: NWConnection, _ head: String) {
        let lines = head.components(separatedBy: "\r\n")
        let request = (lines.first ?? "").split(separator: " ")
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            headers[line[..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        // Only answer requests addressed to this Mac by its loopback name, so a web page
        // elsewhere cannot read the list of devices in the house.
        let names = ["127.0.0.1:\(port)", "localhost:\(port)"]
        guard request.count >= 2, names.contains((headers["host"] ?? "").lowercased()) else {
            send(c, 403, "text/plain; charset=utf-8", Data("Forbidden".utf8))
            return
        }
        var path = ""
        if let beforeQuery = request[1].split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first {
            path = String(beforeQuery)
        }
        if request[0] == "POST" {
            // The dashboard's own buttons. Another web site cannot send the marker header
            // across origins, and a page served from anywhere else is turned away by its Origin.
            let origin = headers["origin"]
            let ownOrigin = origin == nil || names.contains { origin == "http://" + $0 }
            guard headers["x-signal-scan"] == "1", ownOrigin else {
                send(c, 403, "text/plain; charset=utf-8", Data("Forbidden".utf8))
                return
            }
            if onCommand?(path) == true {
                send(c, 200, "application/json; charset=utf-8", Data("{\"ok\":true}".utf8))
            } else {
                send(c, 404, "text/plain; charset=utf-8", Data("Not found".utf8))
            }
            return
        }
        guard request[0] == "GET" else {
            send(c, 405, "text/plain; charset=utf-8", Data("Method not allowed".utf8))
            return
        }
        switch path {
        case "/", "/index.html":
            let file = (webRoot ?? Bundle.main.resourcePath ?? "") + "/dashboard.html"
            if let page = FileManager.default.contents(atPath: file) {
                send(c, 200, "text/html; charset=utf-8", page)
            } else {
                send(c, 500, "text/plain; charset=utf-8", Data("dashboard.html is missing".utf8))
            }
        case "/api/state":
            send(c, 200, "application/json; charset=utf-8", Store.shared.snapshotJSON())
        default:
            send(c, 404, "text/plain; charset=utf-8", Data("Not found".utf8))
        }
    }

    private func send(_ c: NWConnection, _ status: Int, _ type: String, _ body: Data) {
        let reason = [200: "OK", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 500: "Internal Server Error"][status] ?? "OK"
        let head = "HTTP/1.1 \(status) \(reason)\r\n"
            + "Content-Type: \(type)\r\n"
            + "Content-Length: \(body.count)\r\n"
            + "Cache-Control: no-store\r\n"
            + "X-Content-Type-Options: nosniff\r\n"
            + "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src data:\r\n"
            + "Connection: close\r\n\r\n"
        var out = Data(head.utf8)
        out.append(body)
        c.send(content: out, completion: .contentProcessed { _ in c.cancel() })
    }
}
