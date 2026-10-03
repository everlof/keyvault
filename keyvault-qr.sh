# keyvault-qr.sh — sourced by keyvault. The recovery key as a QR code: out, and back in.
#
#   out  on screen under the key (setup, recovery-check --qr) and on a printed recovery sheet
#   in   --camera: a small camera window reads the sheet's QR code (Enter alone at the prompt
#        opens it too); --paste: the clipboard, for an iPhone's Camera app and Universal
#        Clipboard on a new Mac that has no Xcode tools yet
#
# Stock macOS does the work: CoreImage makes the code and AppKit prints it, through JavaScript
# for Automation; the camera window is built once from tools/qr-reader.swift where Xcode's
# command line tools are installed. Recovery never needs any of it: typing the key from paper
# always works.
#
# The key never touches a disk here. It reaches osascript on stdin (argv shows in `ps`), the
# camera window hands it back through a FIFO, and keyvault writes it only into its workspace on
# the RAM disk. Printing is the one exception keyvault cannot avoid: macOS's print system queues
# the page until the printer has taken it.

readonly KV_RECOVERY_PATTERN='^AGE-SECRET-KEY-1[0-9A-Z]+$'

# ---------------------------------------------------------------------------- out

# The key on stdin -> the code's modules as rows of 0/1, 1 dark. CoreImage includes a one-module
# margin; qr_render widens it to the four the standard asks for.
read -r -d '' KV_QR_MATRIX_JXA <<'JXA'
ObjC.import('Foundation'); ObjC.import('CoreImage'); ObjC.import('AppKit');
function run() {
    const data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
    const filter = $.CIFilter.filterWithName('CIQRCodeGenerator');
    filter.setValueForKey(data, 'inputMessage');
    filter.setValueForKey($('M'), 'inputCorrectionLevel');
    const rep = $.NSBitmapImageRep.alloc.initWithCIImage(filter.outputImage);
    const rows = [];
    for (let y = 0; y < rep.pixelsHigh; y++) {
        let row = '';
        for (let x = 0; x < rep.pixelsWide; x++) row += rep.colorAtXY(x, y).brightnessComponent < 0.5 ? '1' : '0';
        rows.push(row);
    }
    return rows.join('\n');
}
JXA

qr_matrix() { osascript -l JavaScript -e "$KV_QR_MATRIX_JXA" 2>/dev/null; }   # the key on stdin

# Rows of 0/1 on stdin -> the code in half blocks, two module rows per line, black on white
# whatever the terminal's colours: a scanner needs the contrast, so even NO_COLOR keeps it.
qr_render() {
    awk -v pad=3 '
        { rows[NR] = $0 }
        END {
            if (NR == 0) exit 1
            w = length(rows[1]) + 2 * pad
            blank = sprintf("%" w "s", ""); gsub(/ /, "0", blank)
            side = substr(blank, 1, pad)
            for (i = 1; i <= pad; i++) all[++m] = blank
            for (i = 1; i <= NR; i++) all[++m] = side rows[i] side
            for (i = 1; i <= pad; i++) all[++m] = blank
            if (m % 2) all[++m] = blank
            for (i = 1; i <= m; i += 2) {
                line = ""
                for (x = 1; x <= w; x++) {
                    t = substr(all[i], x, 1); b = substr(all[i + 1], x, 1)
                    line = line (t == "1" ? (b == "1" ? "█" : "▀") : (b == "1" ? "▄" : " "))
                }
                printf "      \033[30;107m%s\033[0m\n", line
            }
        }'
}

# The key travels as a function argument, which stays inside this shell, and on to osascript
# through a pipe; never through argv, never into a file.
qr_show() {   # qr_show <key> — the code on the terminal
    local rendered
    rendered="$(printf '%s' "$1" | qr_matrix | qr_render)" && [[ -n $rendered ]] || {
        warn "could not draw the QR code here (it needs macOS's CoreImage)"; return 1; }
    printf '\n%s\n\n' "$rendered" >/dev/tty
}

# The recovery sheet: the code large, the key in groups of four, what it is and how to check it.
# Shown in the print dialog; nothing is saved unless the person chooses Save as PDF there. The
# key on stdin; argv: recipient, date, and optionally --pdf PATH (tests, never the key's path).
read -r -d '' KV_QR_SHEET_JXA <<'JXA'
ObjC.import('Foundation'); ObjC.import('CoreImage'); ObjC.import('AppKit');
function label(text, size, weight, mono, color) {
    const field = $.NSTextField.wrappingLabelWithString(text);
    field.font = mono ? $.NSFont.monospacedSystemFontOfSizeWeight(size, weight) : $.NSFont.systemFontOfSizeWeight(size, weight);
    field.textColor = color || $.NSColor.blackColor;
    field.alignment = 0;   // left: lines are centred by their frames, since the enum's values differ by macOS release
    return field;
}
function run(argv) {
    const data = $.NSFileHandle.fileHandleWithStandardInput.readDataToEndOfFile;
    const key = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding).js.trim();
    const recipient = argv[0] || '', made = argv[1] || '', pdf = argv[2] === '--pdf' ? argv[3] : null;
    const application = $.NSApplication.sharedApplication;
    application.setActivationPolicy($.NSApplicationActivationPolicyAccessory);

    const filter = $.CIFilter.filterWithName('CIQRCodeGenerator');
    filter.setValueForKey($(key).dataUsingEncoding($.NSUTF8StringEncoding), 'inputMessage');
    filter.setValueForKey($('M'), 'inputCorrectionLevel');
    const code = filter.outputImage.imageBySamplingNearest.imageByApplyingTransform($.CGAffineTransformMakeScale(12, 12));
    const cg = $.CIContext.contextWithOptions($()).createCGImageFromRect(code, code.extent);
    const side = 260;
    const image = $.NSImage.alloc.initWithCGImageSize(cg, $.NSMakeSize(side, side));
    const picture = $.NSImageView.imageViewWithImage(image);
    picture.imageScaling = $.NSImageScaleProportionallyUpOrDown;

    // As the card writes it: the prefix on its own line, then the rest in fours, five to a line.
    const prefix = 'AGE-SECRET-KEY-1', rest = key.startsWith(prefix) ? key.slice(prefix.length) : key;
    const groups = rest.match(/.{1,4}/g) || [];
    const lines = [];
    for (let i = 0; i < groups.length; i += 5) lines.push(groups.slice(i, i + 5).join(' '));
    const grouped = (key.startsWith(prefix) ? prefix + '\n' : '') + lines.join('\n');
    const grey = $.NSColor.colorWithWhiteAlpha(0.35, 1);
    const views = [
        label('keyvault recovery key', 22, 0.4, false),
        label('Opens this vault on any machine, without Touch ID or the passphrase. Keep this sheet where this Mac is not, and do not photograph it.', 11, 0, false, grey),
        picture,
        label(grouped, 13, 0.2, true),
        label('Check it with the camera:  keyvault recovery-check --camera', 11, 0.2, false),
        label('Restore on a new Mac: the steps are on your keyvault card (keyvault card).', 10, 0, false, grey),
        label('Public key ' + recipient + (made ? '   ·   made ' + made : ''), 8, 0, true, grey),
    ];
    // Placed by hand, top down: each block exactly as wide as its words, centred on the page. Text
    // alignment is left alone: NSTextAlignment's numbers changed between macOS releases.
    const page = $.NSMakeRect(0, 0, 540, 720);
    const container = $.NSView.alloc.initWithFrame(page);
    const column = 460, left = (540 - column) / 2;
    let top = 720 - 40;
    for (const view of views) {
        let height, width = column, x = left;
        if (view === picture) {
            height = side; width = side; x = (540 - side) / 2;
        } else {
            const fitted = view.cell.cellSizeForBounds($.NSMakeRect(0, 0, column, 10000));
            height = fitted.height;
            width = Math.min(Math.ceil(fitted.width) + 2, column);
            x = (540 - width) / 2;
        }
        top -= height;
        view.frame = $.NSMakeRect(x, top, width, height);
        container.addSubview(view);
        top -= 14;
    }

    const operation = pdf
        ? $.NSPrintOperation.PDFOperationWithViewInsideRectToPathPrintInfo(container, page, pdf, $.NSPrintInfo.sharedPrintInfo)
        : $.NSPrintOperation.printOperationWithView(container);
    operation.jobTitle = 'keyvault recovery sheet';
    operation.showsPrintPanel = !pdf;
    operation.showsProgressPanel = false;
    if (!pdf) application.activateIgnoringOtherApps(true);
    return operation.runOperation ? 'printed' : 'cancelled';
}
JXA

qr_print() {   # qr_print <key> — the print dialog with the recovery sheet; 0 when printed
    local result
    result="$(printf '%s' "$1" | osascript -l JavaScript -e "$KV_QR_SHEET_JXA" "$(recipient_of recovery)" "$(date +%F)" \
              ${KEYVAULT_QR_SHEET_PDF:+--pdf "$KEYVAULT_QR_SHEET_PDF"} 2>/dev/null)"
    [[ $result == printed ]]
}

# After a key has been shown or checked: the code on screen, a sheet if asked for, then the
# screen and its scrollback cleared, as setup does with the key itself.
qr_offer() {   # qr_offer <key>
    qr_show "$1" || return 0
    local answer
    { exec 5</dev/tty; } 2>/dev/null || return 0
    printf '  Print a recovery sheet with this QR code? [y/N] ' >/dev/tty
    IFS= read -r answer <&5
    if [[ $answer == [yY]* ]]; then
        if qr_print "$1"; then ok "sent to the printer"; else warn "not printed"; fi
    fi
    printf '  Press Enter to clear the screen. ' >/dev/tty
    IFS= read -r answer <&5
    exec 5<&-
    printf '\033[2J\033[3J\033[H' >/dev/tty 2>/dev/null
}

# ---------------------------------------------------------------------------- in

# The camera window, built from tools/qr-reader.swift into an app bundle of its own the first
# time it is needed, so macOS asks for the camera in its name. Rebuilt when the source or the
# compiler changes; ad-hoc signed, which is all a local app needs.
qr_reader_app() {
    [[ -n ${KEYVAULT_QR_READER_APP:-} ]] && { printf '%s\n' "$KEYVAULT_QR_READER_APP"; return 0; }
    local src="$KV_ROOT/tools/qr-reader.swift" id app
    [[ -f $src ]] || return 1
    xcode-select -p >/dev/null 2>&1 && have swiftc || return 1    # never wake the install prompt
    id="$( { cat "$src"; swiftc --version 2>/dev/null; } | shasum -a 256 | cut -c1-16)"
    app="$KV_STATE/qr-reader/$id/keyvault QR reader.app"
    if [[ ! -x $app/Contents/MacOS/qr-reader ]]; then
        info "  Building the camera reader, once (a few seconds)…"
        rm -rf "$KV_STATE/qr-reader"
        mkdir -p "$app/Contents/MacOS" || return 1
        swiftc -O -swift-version 5 -o "$app/Contents/MacOS/qr-reader" "$src" 2>/dev/null \
            || { rm -rf "$KV_STATE/qr-reader"; return 1; }
        cat > "$app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key><string>local.keyvault.qr-reader</string>
    <key>CFBundleName</key><string>keyvault QR reader</string>
    <key>CFBundleExecutable</key><string>qr-reader</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSCameraUsageDescription</key><string>keyvault reads the QR code on your recovery sheet. Nothing is recorded or saved.</string>
</dict>
</plist>
PLIST
        codesign --force --sign - "$app" >/dev/null 2>&1 || { rm -rf "$KV_STATE/qr-reader"; return 1; }
    fi
    printf '%s\n' "$app"
}

qr_can_read() { [[ -n ${KEYVAULT_QR_READER_BIN:-} ]] || qr_reader_app >/dev/null 2>&1; }

qr_read() {   # qr_read <out> — the key off its QR code, into <out> (on the RAM disk)
    local out="$1" app fifo errors reader
    if [[ -n ${KEYVAULT_QR_READER_BIN:-} ]]; then          # tests: stands in for the camera
        ( umask 077; "$KEYVAULT_QR_READER_BIN" | head -1 > "$out" )
        [[ -s $out ]] || { info "keyvault: no QR code was read"; return 1; }
        return 0
    fi
    app="$(qr_reader_app)" || {
        info "keyvault: no camera reader on this Mac: it is built with Xcode's tools (xcode-select --install)."
        info "          Type the key instead, or scan it with the iPhone's Camera app, copy it, and use --paste."
        return 1; }
    fifo="$(dirname "$out")/qr.fifo"; errors="$(dirname "$out")/qr.errors"
    rm -f "$fifo" "$errors"
    mkfifo -m 600 "$fifo" || return 1
    ( umask 077; head -1 < "$fifo" > "$out" ) &
    reader=$!
    # Hold a write end ourselves, opened after the reader forked so it holds none: closing it is
    # the reader's end of file, whether the window wrote a key, nothing, or never opened. Opening
    # one only once the window is gone could wait forever on a reader that had already left.
    exec 6>"$fifo"
    info "  A camera window is open: hold the QR code of your recovery key up to it."
    # KEYVAULT_QR_READER_IMAGE: tests hand the real app a picture instead of the camera.
    open -W -n --stdout "$fifo" --stderr "$errors" "$app" --args --pattern "$KV_RECOVERY_PATTERN" \
        ${KEYVAULT_QR_READER_IMAGE:+--image "$KEYVAULT_QR_READER_IMAGE"}
    exec 6>&-
    wait "$reader"
    rm -f "$fifo"
    if [[ ! -s $out ]]; then
        info "keyvault: $(head -1 "$errors" 2>/dev/null | grep . || echo "no QR code was read")"
        rm -f "$errors" "$out"
        return 1
    fi
    rm -f "$errors"
}

clipboard_read() {   # clipboard_read <out> — the key from the clipboard, which is then emptied
    local out="$1" k
    k="$("${KEYVAULT_CLIPBOARD_BIN:-pbpaste}" 2>/dev/null)"
    "${KEYVAULT_CLIPBOARD_CLEAR_BIN:-pbcopy}" </dev/null >/dev/null 2>&1
    [[ -n $k ]] || { info "keyvault: the clipboard is empty"; return 1; }
    ( umask 077; printf '%s\n' "$k" > "$out" )
    k=""
}
