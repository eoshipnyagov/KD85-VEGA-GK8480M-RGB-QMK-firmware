#!/usr/bin/env python3
"""Read-only Frida hook for HID feature reports in the vendor utility."""

from __future__ import annotations

import argparse
import json
import time

import frida


HOOK = r"""
function hookBufferFunction(moduleName, functionName, bufferArg, lengthArg) {
    let address;
    try {
        address = Process.getModuleByName(moduleName).getExportByName(functionName);
    } catch (_) {
        send({missing: functionName});
        return;
    }
    send({hooked: functionName, address: address.toString()});
    Interceptor.attach(address, {
        onEnter(args) {
            const length = args[lengthArg].toInt32();
            this.handle = args[0];
            this.length = length;
            const meta = {source: functionName, handle: this.handle.toString(), length: length};
            if (length > 0 && length <= 1048576 && !args[bufferArg].isNull())
                send(meta, args[bufferArg].readByteArray(length));
            else
                send(meta);
        },
        onLeave(retval) {
            send({source: functionName + ':return', handle: this.handle.toString(), retval: retval.toString()});
        }
    });
}

const getFeature = Process.getModuleByName('hid.dll').getExportByName('HidD_GetFeature');
send({hooked: 'HidD_GetFeature', address: getFeature.toString()});
Interceptor.attach(getFeature, {
    onEnter(args) {
        this.buffer = args[1];
        this.length = args[2].toInt32();
    },
    onLeave(retval) {
        send({source: 'HidD_GetFeature:return', retval: retval.toString(), length: this.length});
        if (retval.toInt32() !== 0 && this.length > 0 && this.length <= 4096 && !this.buffer.isNull()) {
            send({source: 'HidD_GetFeature', length: this.length}, this.buffer.readByteArray(this.length));
        }
    }
});

hookBufferFunction('hid.dll', 'HidD_SetFeature', 1, 2);
hookBufferFunction('hid.dll', 'HidD_SetOutputReport', 1, 2);
hookBufferFunction('kernel32.dll', 'WriteFile', 1, 2);

const deviceIoControl = Process.getModuleByName('kernel32.dll').getExportByName('DeviceIoControl');
send({hooked: 'DeviceIoControl', address: deviceIoControl.toString()});
Interceptor.attach(deviceIoControl, {
    onEnter(args) {
        this.handle = args[0];
        this.code = args[1].toUInt32();
        this.inBuffer = args[2];
        this.inLength = args[3].toUInt32();
        this.outBuffer = args[4];
        this.outLength = args[5].toUInt32();
        if (this.inLength > 0 && this.inLength <= 4096 && !this.inBuffer.isNull()) {
            send({source: 'DeviceIoControl:in', handle: this.handle.toString(), code: this.code, length: this.inLength}, this.inBuffer.readByteArray(this.inLength));
        } else {
            send({source: 'DeviceIoControl:in', handle: this.handle.toString(), code: this.code, length: this.inLength});
        }
    },
    onLeave(retval) {
        send({source: 'DeviceIoControl:return', handle: this.handle.toString(), code: this.code, retval: retval.toString(), out_length: this.outLength});
        if (retval.toInt32() !== 0 && this.outLength > 0 && this.outLength <= 4096 && !this.outBuffer.isNull()) {
            send({source: 'DeviceIoControl:out', handle: this.handle.toString(), code: this.code, length: this.outLength}, this.outBuffer.readByteArray(this.outLength));
        }
    }
});

function hookCreateFile(name) {
    let address;
    try { address = Process.getModuleByName('kernel32.dll').getExportByName(name); } catch (_) { return; }
    Interceptor.attach(address, {
        onEnter(args) { this.path = args[0].readUtf16String(); },
        onLeave(retval) { send({source: name, path: this.path, handle: retval.toString()}); }
    });
}
hookCreateFile('CreateFileW');
"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture HidD_SetFeature calls")
    parser.add_argument("--process", default="Vega Screen Software.exe")
    parser.add_argument("--seconds", type=float, default=120.0)
    args = parser.parse_args()

    device = frida.get_local_device()
    matches = [p for p in device.enumerate_processes() if p.name.lower() == args.process.lower()]
    if len(matches) != 1:
        raise SystemExit(f"expected one process named {args.process!r}, found {len(matches)}")

    session = device.attach(matches[0].pid)

    def on_message(message, data):
        if message.get("type") == "send":
            payload = message["payload"]
            if data is not None:
                payload = dict(payload)
                payload["hex"] = bytes(data).hex(" ")
                payload["data"] = list(data)
            print(json.dumps(payload, ensure_ascii=False), flush=True)
        else:
            print(json.dumps(message, ensure_ascii=False), flush=True)

    script = session.create_script(HOOK)
    script.on("message", on_message)
    script.load()
    print(json.dumps({"attached_pid": matches[0].pid, "read_only": True}), flush=True)
    try:
        time.sleep(args.seconds)
    finally:
        session.detach()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
