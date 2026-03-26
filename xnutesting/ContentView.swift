//
//  ContentView.swift
//  xnutesting
//
//  XNU AIO Kevent Use-After-Free — UI Harness
//

import SwiftUI

// MARK: - Log capture

final class LogCapture: ObservableObject {
    @Published var lines: [String] = []
    private var originalStdout: Int32 = -1
    private var originalStderr: Int32 = -1
    private var pipeRead: Int32 = -1
    private var pipeWrite: Int32 = -1
    private var captureThread: Thread?

    func start() {
        var fds: [Int32] = [0, 0]
        pipe(&fds)
        pipeRead = fds[0]
        pipeWrite = fds[1]

        // Redirect both stdout AND stderr → same write-end
        // printf → stdout, NSLog → stderr; both route to our pipe
        originalStdout = dup(STDOUT_FILENO)
        originalStderr = dup(STDERR_FILENO)
        dup2(pipeWrite, STDOUT_FILENO)
        dup2(pipeWrite, STDERR_FILENO)

        let readFd = pipeRead
        captureThread = Thread {
            var buf = [UInt8](repeating: 0, count: 8192)
            while true {
                let n = read(readFd, &buf, buf.count - 1)
                if n <= 0 { break }
                buf[n] = 0
                if let s = String(bytes: buf[0..<n], encoding: .utf8) {
                    // NSLog lines: "2026-03-26 13:48:05.123 app[pid:tid] [AIO-UAF] ..."
                    // Strip the verbose timestamp prefix for cleaner display
                    let cleaned = s.components(separatedBy: "\n").compactMap { raw -> String? in
                        let line = raw.trimmingCharacters(in: .whitespaces)
                        guard !line.isEmpty else { return nil }
                        if let range = line.range(of: #"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \S+\[\d+:\d+\] "#,
                                                  options: .regularExpression) {
                            return String(line[range.upperBound...])
                        }
                        return line
                    }
                    for line in cleaned {
                        DispatchQueue.main.async { [weak self] in
                            self?.lines.append(line)
                        }
                    }
                }
            }
        }
        captureThread?.start()
    }

    func stop() {
        fflush(stdout)
        if originalStdout != -1 { dup2(originalStdout, STDOUT_FILENO); close(originalStdout); originalStdout = -1 }
        if originalStderr != -1 { dup2(originalStderr, STDERR_FILENO); close(originalStderr); originalStderr = -1 }
        if pipeWrite != -1 { close(pipeWrite); pipeWrite = -1 }
    }

    func clear() { lines = [] }
}

// MARK: - Main View

struct ContentView: View {
    @StateObject private var log = LogCapture()
    @State private var running = false
    @State private var lastResult: String? = nil

    var body: some View {
        ZStack {
            // Background
            LinearGradient(
                gradient: Gradient(colors: [
                    Color(red: 0.05, green: 0.05, blue: 0.10),
                    Color(red: 0.08, green: 0.04, blue: 0.14)
                ]),
                startPoint: .topLeading, endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 0) {
                // Header
                VStack(spacing: 6) {
                    HStack(spacing: 10) {
                        Image(systemName: "cpu.fill")
                            .font(.title2)
                            .foregroundColor(.red)
                        Text("XNU AIO UAF")
                            .font(.system(.title2, design: .monospaced, weight: .bold))
                            .foregroundColor(.white)
                    }
                    Text("CVE-2026-XXXX · iOS 26.2 · bsd/kern/kern_aio.c")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(Color(white: 0.55))
                }
                .padding(.top, 20)
                .padding(.bottom, 16)

                // Status badge
                if let result = lastResult {
                    Text(result)
                        .font(.system(.caption, design: .monospaced, weight: .semibold))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 6)
                        .background(
                            result.contains("DOUBLE-FREE") || result.contains("won")
                                ? Color.red.opacity(0.25)
                                : Color.orange.opacity(0.2)
                        )
                        .foregroundColor(
                            result.contains("DOUBLE-FREE") || result.contains("won")
                                ? .red
                                : .orange
                        )
                        .clipShape(Capsule())
                        .transition(.scale.combined(with: .opacity))
                        .padding(.bottom, 12)
                }

                // — Buttons —
                VStack(spacing: 12) {
                    // Button 1: ObjC UAF (Double-Free)
                    ExploitButton(
                        label: "Run Double-Free UAF",
                        subtitle: "ex.m · aio_kevent_uaf_trigger()",
                        icon: "bolt.trianglebadge.exclamationmark.fill",
                        accent: Color(red: 0.85, green: 0.15, blue: 0.2),
                        running: running
                    ) {
                        runExploit(label: "UAF") {
                            aio_kevent_uaf_trigger()
                        }
                    }

                    // Button 2: C PoC (Panic)
                    ExploitButton(
                        label: "Run Kernel Panic PoC",
                        subtitle: "ex_PoC.c · aio_kevent_PoC_trigger()",
                        icon: "exclamationmark.triangle.fill",
                        accent: Color(red: 0.9, green: 0.5, blue: 0.1),
                        running: running
                    ) {
                        runExploit(label: "PANIC") {
                            aio_kevent_PoC_trigger()
                        }
                    }

                    // Button 3: Combined UAF + ICMPv6 KRW chain
                    ExploitButton(
                        label: "Run Combined KRW Chain",
                        subtitle: "ex_combined.m · AIO UAF → ICMPv6 KRW",
                        icon: "link.badge.plus",
                        accent: Color(red: 0.45, green: 0.3, blue: 0.95),
                        running: running
                    ) {
                        runExploit(label: "CHAIN") {
                            ex_combined_trigger()
                        }
                    }

                    // Button 4: darksword physical KRW
                    ExploitButton(
                        label: "Run Darksword KRW",
                        subtitle: "dsw.m · dsw_main() · physical mem KRW",
                        icon: "memorychip.fill",
                        accent: Color(red: 0.1, green: 0.75, blue: 0.65),
                        running: running
                    ) {
                        runExploit(label: "DSW") {
                            dsw_main()
                        }
                    }
                }
                .padding(.horizontal, 20)

                // Divider
                HStack(spacing: 8) {
                    Rectangle().fill(Color.white.opacity(0.08)).frame(height: 1)
                    Text("OUTPUT")
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .foregroundColor(Color(white: 0.35))
                    Rectangle().fill(Color.white.opacity(0.08)).frame(height: 1)
                }
                .padding(.horizontal, 20)
                .padding(.vertical, 16)

                // Log area
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            if log.lines.isEmpty {
                                Text("// Press a button to execute the exploit")
                                    .font(.system(size: 12, design: .monospaced))
                                    .foregroundColor(Color(white: 0.3))
                                    .padding(.top, 8)
                            }
                            ForEach(Array(log.lines.enumerated()), id: \.offset) { idx, line in
                                Text(line)
                                    .font(.system(size: 12, design: .monospaced))
                                    .foregroundColor(logColor(for: line))
                                    .id(idx)
                            }
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .onChange(of: log.lines.count) { _ in
                        if let last = log.lines.indices.last {
                            withAnimation { proxy.scrollTo(last, anchor: .bottom) }
                        }
                    }
                }
                .background(Color(white: 0.04).opacity(0.9))
                .clipShape(RoundedRectangle(cornerRadius: 14))
                .overlay(
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color.white.opacity(0.07), lineWidth: 1)
                )
                .padding(.horizontal, 20)
                .padding(.bottom, 12)

                // Clear button
                Button {
                    withAnimation { log.clear(); lastResult = nil }
                } label: {
                    Label("Clear", systemImage: "trash")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(Color(white: 0.45))
                }
                .padding(.bottom, 20)
            }
        }
        .onAppear { log.start() }
        .onDisappear { log.stop() }
    }

    // MARK: - Helpers

    private func runExploit(label: String, fn: @escaping () -> Void) {
        guard !running else { return }
        running = true
        log.clear()
        lastResult = nil
        log.lines.append("[\(label)] Starting...")

        DispatchQueue.global(qos: .userInitiated).async {
            fn()
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                running = false
                let result = log.lines.last(where: { $0.contains("DOUBLE-FREE") || $0.contains("won") || $0.contains("panic") })
                    ?? log.lines.last
                withAnimation { lastResult = result }
            }
        }
    }

    private func logColor(for line: String) -> Color {
        if line.contains("DOUBLE-FREE") || line.contains("panic") { return .red }
        if line.contains("***") { return Color(red: 1, green: 0.4, blue: 0.4) }
        if line.contains("[+]") || line.contains("ACHIEVED") { return Color(red: 0.3, green: 1, blue: 0.5) }
        if line.contains("[-]") || line.contains("timeout") { return .orange }
        if line.contains("WARNING") { return .yellow }
        if line.contains("0x") { return Color(red: 0.6, green: 0.85, blue: 1.0) }
        return Color(white: 0.75)
    }
}

// MARK: - ExploitButton

struct ExploitButton: View {
    let label: String
    let subtitle: String
    let icon: String
    let accent: Color
    let running: Bool
    let action: () -> Void

    @State private var pressed = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 14) {
                ZStack {
                    Circle()
                        .fill(accent.opacity(0.18))
                        .frame(width: 44, height: 44)
                    Image(systemName: running ? "ellipsis" : icon)
                        .font(.system(size: 20, weight: .semibold))
                        .foregroundColor(accent)
                        .symbolEffect(.pulse, isActive: running)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text(label)
                        .font(.system(.callout, design: .monospaced, weight: .bold))
                        .foregroundColor(.white)
                    Text(subtitle)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(Color(white: 0.45))
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(Color(white: 0.3))
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(Color(white: 0.07))
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(accent.opacity(pressed ? 0.6 : 0.2), lineWidth: 1)
                    )
            )
            .scaleEffect(pressed ? 0.97 : 1.0)
            .animation(.spring(response: 0.2, dampingFraction: 0.7), value: pressed)
        }
        .disabled(running)
        .opacity(running ? 0.6 : 1.0)
        .buttonStyle(.plain)
        .simultaneousGesture(DragGesture(minimumDistance: 0)
            .onChanged { _ in pressed = true }
            .onEnded { _ in pressed = false })
    }
}

#Preview {
    ContentView()
}

