// qr-reader.swift — keyvault's camera reader for the QR code on a recovery sheet.
//
// keyvault-qr.sh builds this on first use into an app bundle of its own and starts it with
// `open`, so macOS asks for the camera in this app's name, not the terminal's. A terminal that
// may not use the camera (an agent host, say) would otherwise get nothing, silently.
//
// It shows the camera, reads QR codes with Vision, writes the first one matching --pattern to
// stdout, and quits. Nothing is recorded or saved: a frame lives in memory while Vision looks at
// it. Exit 0 with the text on stdout; otherwise a reason on stderr and a non-zero status.
import AppKit
import AVFoundation
import Vision

final class Reader: NSObject, NSApplicationDelegate, NSWindowDelegate,
                    AVCaptureVideoDataOutputSampleBufferDelegate {
    private let session = AVCaptureSession()
    private let frames = DispatchQueue(label: "keyvault.qr-reader.frames")
    private let pattern: NSRegularExpression
    private let prompt: String
    private var window: NSWindow?
    private var frameCount = 0          // frames queue only
    private var found = false           // frames queue only
    private var finished = false        // main thread only

    init(pattern: NSRegularExpression, prompt: String) {
        self.pattern = pattern
        self.prompt = prompt
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        AVCaptureDevice.requestAccess(for: .video) { granted in
            DispatchQueue.main.async {
                if granted { self.start() } else {
                    self.finish(3, "camera access was refused: System Settings › Privacy & Security › Camera")
                }
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 180) {
            self.finish(2, "no QR code was read within 3 minutes")
        }
    }

    private func start() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device), session.canAddInput(input) else {
            return finish(3, "no camera on this Mac")
        }
        session.addInput(input)
        let output = AVCaptureVideoDataOutput()
        output.alwaysDiscardsLateVideoFrames = true
        output.setSampleBufferDelegate(self, queue: frames)
        guard session.canAddOutput(output) else { return finish(3, "the camera cannot be read") }
        session.addOutput(output)

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        let camera = NSView()
        camera.wantsLayer = true
        camera.layer = preview
        camera.translatesAutoresizingMaskIntoConstraints = false

        let label = NSTextField(wrappingLabelWithString: prompt)
        label.font = .systemFont(ofSize: 14, weight: .medium)
        label.alignment = .center
        let note = NSTextField(wrappingLabelWithString: "Nothing is recorded or saved. The window closes when the key is read.")
        note.font = .systemFont(ofSize: 11)
        note.textColor = .secondaryLabelColor
        note.alignment = .center
        let cancel = NSButton(title: "Cancel", target: self, action: #selector(cancelled))
        cancel.keyEquivalent = "\u{1b}"

        let stack = NSStackView(views: [camera, label, note, cancel])
        stack.orientation = .vertical
        stack.spacing = 10
        stack.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        NSLayoutConstraint.activate([
            camera.widthAnchor.constraint(equalToConstant: 480),
            camera.heightAnchor.constraint(equalToConstant: 360),
            label.widthAnchor.constraint(equalTo: camera.widthAnchor),
            note.widthAnchor.constraint(equalTo: camera.widthAnchor),
        ])

        let window = NSWindow(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "keyvault — scan the recovery key"
        window.contentView = stack
        window.delegate = self
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        self.window = window
        frames.async { self.session.startRunning() }
    }

    func captureOutput(_ output: AVCaptureOutput, didOutput sampleBuffer: CMSampleBuffer,
                       from connection: AVCaptureConnection) {
        frameCount += 1
        guard !found, frameCount % 3 == 0, let pixels = CMSampleBufferGetImageBuffer(sampleBuffer) else { return }
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        try? VNImageRequestHandler(cvPixelBuffer: pixels, options: [:]).perform([request])
        for result in request.results ?? [] {
            guard let text = result.payloadStringValue,
                  pattern.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil else { continue }
            found = true
            session.stopRunning()
            FileHandle.standardOutput.write(Data((text + "\n").utf8))
            DispatchQueue.main.async { self.finish(0, nil) }
            return
        }
    }

    @objc private func cancelled() { finish(1, "cancelled") }

    func windowWillClose(_ notification: Notification) { finish(1, "cancelled") }

    private func finish(_ status: Int32, _ message: String?) {
        guard !finished else { return }
        finished = true
        if let message { FileHandle.standardError.write(Data((message + "\n").utf8)) }
        frames.async {
            self.session.stopRunning()
            DispatchQueue.main.async { exit(status) }
        }
    }
}

var arguments = CommandLine.arguments.dropFirst().makeIterator()
var patternText = "^AGE-SECRET-KEY-1[0-9A-Z]+$"
var prompt = "Hold the QR code of your keyvault recovery key up to the camera."
while let argument = arguments.next() {
    switch argument {
    case "--pattern": patternText = arguments.next() ?? patternText
    case "--prompt": prompt = arguments.next() ?? prompt
    default: break
    }
}
guard let pattern = try? NSRegularExpression(pattern: patternText) else {
    FileHandle.standardError.write(Data("invalid --pattern\n".utf8))
    exit(64)
}
// --image PATH reads one picture instead of the camera: how the tests prove the bundle, the FIFO
// and Vision end to end on a machine with no camera to point at a sheet.
if let index = CommandLine.arguments.firstIndex(of: "--image"), index + 1 < CommandLine.arguments.count {
    let path = CommandLine.arguments[index + 1]
    guard let image = NSImage(contentsOfFile: path),
          let cgImage = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
        FileHandle.standardError.write(Data("cannot read \(path)\n".utf8))
        exit(66)
    }
    let request = VNDetectBarcodesRequest()
    request.symbologies = [.qr]
    try? VNImageRequestHandler(cgImage: cgImage, options: [:]).perform([request])
    for result in request.results ?? [] {
        if let text = result.payloadStringValue,
           pattern.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) != nil {
            FileHandle.standardOutput.write(Data((text + "\n").utf8))
            exit(0)
        }
    }
    FileHandle.standardError.write(Data("no recovery key QR code in that picture\n".utf8))
    exit(1)
}

let application = NSApplication.shared
let reader = Reader(pattern: pattern, prompt: prompt)
application.delegate = reader
application.run()
