
// ws_hook_burp_crossplatform.js

let sendPtr, recvPtr;

if (Process.platform === 'windows') {
    sendPtr = Module.getExportByName('ws2_32.dll', 'send');
    recvPtr = Module.getExportByName('ws2_32.dll', 'recv');
} else if (Process.platform === 'darwin' || Process.platform === 'linux') {
    sendPtr = Module.getExportByName(null, 'send');
    recvPtr = Module.getExportByName(null, 'recv');
}

if (sendPtr && recvPtr) {
    // send 후킹
    Interceptor.attach(sendPtr, {
        onEnter: function(args) {
            const buffer = args[1];
            const length = args[2].toInt32();
            if (length > 0) {
                const originalData = Memory.readByteArray(buffer, length);
                send({ type: 'packet', direction: 'send', payload: arrayBufferToHex(originalData) });
                const op = recv('modified_data', function(value) {
                    const modifiedPayload = hexToByteArray(value.payload);
                    Memory.writeByteArray(buffer, modifiedPayload);
                    args[2] = ptr(modifiedPayload.length);
                });
                op.wait();
            }
        }
    });

    // recv 후킹
    Interceptor.attach(recvPtr, {
        onEnter: function(args) { this.buffer = args[1]; },
        onLeave: function(retval) {
            const bytesReceived = retval.toInt32();
            if (bytesReceived > 0) {
                const originalData = Memory.readByteArray(this.buffer, bytesReceived);
                send({ type: 'packet', direction: 'recv', payload: arrayBufferToHex(originalData) });
                const op = recv('modified_data', function(value) {
                    const modifiedPayload = hexToByteArray(value.payload);
                    Memory.writeByteArray(this.buffer, modifiedPayload);
                    retval.replace(modifiedPayload.length);
                });
                op.wait();
            }
        }
    });

    // Helper functions
    function arrayBufferToHex(buffer) { return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join(''); }
    function hexToByteArray(hexString) { for (var bytes = [], c = 0; c < hexString.length; c += 2) bytes.push(parseInt(hexString.substr(c, 2), 16)); return bytes; }
    
    console.log('[*] Cross-platform Frida hook script for Burp is now running.');
} else {
    console.error('[!] Could not find send/recv functions for this platform.');
}