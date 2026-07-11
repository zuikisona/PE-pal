'use strict';

function postProgress(msg, pct) {
    self.postMessage({ type: 'progress', message: msg, percent: pct });
}
function calcEntropy(bytes) {
    if (!bytes || bytes.length === 0) return 0;
    const freq = new Uint32Array(256);
    for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
    let e = 0;
    const n = bytes.length;
    for (let i = 0; i < 256; i++) {
        if (freq[i] === 0) continue;
        const p = freq[i] / n;
        e -= p * Math.log2(p);
    }
    return e;
}
function rvaToOffset(rva, sections) {
    if (rva === 0) return 0;
    for (const s of sections) {
        const vEnd = s.virtualAddress + Math.max(s.virtualSize, s.sizeOfRawData);
        if (rva >= s.virtualAddress && rva < vEnd) {
            return s.pointerToRawData + (rva - s.virtualAddress);
        }
    }
    return rva;
}
function readCStr(dv, offset, maxLen) {
    maxLen = maxLen || 512;
    if (offset < 0 || offset >= dv.byteLength) return '';
    let s = '';
    for (let i = 0; i < maxLen && offset + i < dv.byteLength; i++) {
        const c = dv.getUint8(offset + i);
        if (c === 0) break;
        s += String.fromCharCode(c);
    }
    return s;
}
var API_CAT = {
    'CreateRemoteThread': 'Process Injection',
    'CreateRemoteThreadEx': 'Process Injection',
    'VirtualAllocEx': 'Process Injection',
    'VirtualAlloc': 'Process Injection',
    'WriteProcessMemory': 'Process Injection',
    'NtCreateThreadEx': 'Process Injection',
    'RtlCreateUserThread': 'Process Injection',
    'QueueUserAPC': 'Process Injection',
    'OpenProcess': 'Process Injection',
    'NtUnmapViewOfSection': 'Process Injection',
    'NtMapViewOfSection': 'Process Injection',
    'SetWindowsHookEx': 'Process Injection',
    'URLDownloadToFile': 'Networking',
    'URLDownloadToFileA': 'Networking',
    'URLDownloadToFileW': 'Networking',
    'InternetOpen': 'Networking',
    'InternetOpenA': 'Networking',
    'InternetOpenW': 'Networking',
    'InternetConnect': 'Networking',
    'InternetConnectA': 'Networking',
    'InternetConnectW': 'Networking',
    'HttpOpenRequest': 'Networking',
    'HttpOpenRequestA': 'Networking',
    'HttpSendRequest': 'Networking',
    'HttpSendRequestA': 'Networking',
    'WSAStartup': 'Networking',
    'socket': 'Networking',
    'connect': 'Networking',
    'send': 'Networking',
    'recv': 'Networking',
    'WinHttpOpen': 'Networking',
    'WinHttpConnect': 'Networking',
    'WinHttpSendRequest': 'Networking',
    'RegSetValueEx': 'Registry',
    'RegSetValueExA': 'Registry',
    'RegSetValueExW': 'Registry',
    'RegCreateKeyEx': 'Registry',
    'RegCreateKeyExA': 'Registry',
    'RegCreateKeyExW': 'Registry',
    'RegOpenKeyEx': 'Registry',
    'RegOpenKeyExA': 'Registry',
    'RegDeleteKey': 'Registry',
    'RegDeleteKeyA': 'Registry',
    'RegDeleteValue': 'Registry',
    'CreateFile': 'File System',
    'CreateFileA': 'File System',
    'CreateFileW': 'File System',
    'DeleteFile': 'File System',
    'DeleteFileA': 'File System',
    'WriteFile': 'File System',
    'ReadFile': 'File System',
    'CopyFile': 'File System',
    'CopyFileA': 'File System',
    'MoveFile': 'File System',
    'MoveFileA': 'File System',
    'FindFirstFile': 'File System',
    'FindFirstFileA': 'File System',
    'IsDebuggerPresent': 'Anti-Analysis',
    'CheckRemoteDebuggerPresent': 'Anti-Analysis',
    'NtQueryInformationProcess': 'Anti-Analysis',
    'GetTickCount': 'Anti-Analysis',
    'QueryPerformanceCounter': 'Anti-Analysis',
    'Sleep': 'Anti-Analysis',
    'OutputDebugString': 'Anti-Analysis',
    'OutputDebugStringA': 'Anti-Analysis',
    'NtSetInformationThread': 'Anti-Analysis',
    'GetAsyncKeyState': 'Keylogging',
    'GetKeyState': 'Keylogging',
    'SetWindowsHookExA': 'Keylogging',
    'SetWindowsHookExW': 'Keylogging',
    'GetClipboardData': 'Keylogging',
    'AdjustTokenPrivileges': 'Privilege Escalation',
    'OpenProcessToken': 'Privilege Escalation',
    'LookupPrivilegeValue': 'Privilege Escalation',
    'LookupPrivilegeValueA': 'Privilege Escalation',
    'CryptAcquireContext': 'Crypto/Obfuscation',
    'CryptAcquireContextA': 'Crypto/Obfuscation',
    'CryptEncrypt': 'Crypto/Obfuscation',
    'CryptDecrypt': 'Crypto/Obfuscation',
    'CryptGenKey': 'Crypto/Obfuscation',
    'CreateServiceA': 'Persistence',
    'CreateServiceW': 'Persistence',
    'StartService': 'Persistence',
    'StartServiceA': 'Persistence',
    'ShellExecute': 'Persistence',
    'ShellExecuteA': 'Persistence',
    'ShellExecuteW': 'Persistence',
    'WinExec': 'Persistence',
};
function parseIAT(dv, sections, is64, dataDirectories) {
    var imports = [];
    var apiCategories = {};
    try {
        var dir = dataDirectories[1];
        if (!dir || !dir.rva || !dir.size) return { imports: imports, apiCategories: apiCategories };

        var descOff = rvaToOffset(dir.rva, sections);
        var maxDescs = Math.floor(dir.size / 20) + 1;

        for (var di = 0; di < maxDescs && descOff + 20 <= dv.byteLength; di++) {
            var origThunk  = dv.getUint32(descOff,      true);
            var nameRVA    = dv.getUint32(descOff + 12, true);
            var firstThunk = dv.getUint32(descOff + 16, true);

            if (!nameRVA && !firstThunk) break; 

            var nameOff = rvaToOffset(nameRVA, sections);
            var dllName = readCStr(dv, nameOff);
            if (!dllName) { descOff += 20; continue; }

            var functions = [];
            var thunkRVA  = origThunk || firstThunk;
            var thunkOff  = rvaToOffset(thunkRVA, sections);
            var thunkStep = is64 ? 8 : 4;

            for (var ti = 0; ti < 1024 && thunkOff + thunkStep <= dv.byteLength; ti++) {
                var loWord = dv.getUint32(thunkOff, true);
                var hiWord = is64 ? dv.getUint32(thunkOff + 4, true) : 0;

                if (loWord === 0 && hiWord === 0) break;

                var isOrdinal = is64 ? ((hiWord & 0x80000000) !== 0) : ((loWord & 0x80000000) !== 0);

                if (isOrdinal) {
                    functions.push('Ordinal #' + (loWord & 0xFFFF));
                } else {
                    var hintRVA = is64 ? loWord : (loWord & 0x7FFFFFFF);
                    var hintOff = rvaToOffset(hintRVA, sections);
                    if (hintOff + 2 < dv.byteLength) {
                        var fnName = readCStr(dv, hintOff + 2);
                        if (fnName) {
                            functions.push(fnName);
                            if (API_CAT[fnName]) {
                                var cat = API_CAT[fnName];
                                apiCategories[cat] = (apiCategories[cat] || 0) + 1;
                            }
                        }
                    }
                }
                thunkOff += thunkStep;
            }

            imports.push({ dll: dllName, functions: functions });
            descOff += 20;
        }
    } catch(e) {  }

    return { imports: imports, apiCategories: apiCategories };
}
function extractStrings(bytes) {
    var results = [];
    var MIN_LEN = 4;
    var LIMIT   = 1000;
    var cur = '';
    var startOff = 0;

    for (var i = 0; i < bytes.length && results.length < LIMIT; i++) {
        var b = bytes[i];
        if (b >= 0x20 && b <= 0x7E) {
            if (cur.length === 0) startOff = i;
            cur += String.fromCharCode(b);
        } else {
            if (cur.length >= MIN_LEN) {
                var flags = [];
                if (/https?:\/\/|ftp:\/\//i.test(cur))                    flags.push('url');
                if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(cur))      flags.push('ip');
                if (/[a-zA-Z]:\\|\.dll|\.exe|\.bat|\.ps1|\.vbs/i.test(cur)) flags.push('path');
                results.push({ value: cur, offset: startOff, flags: flags });
            }
            cur = '';
        }
    }
    if (cur.length >= MIN_LEN) {
        var flags2 = [];
        if (/https?:\/\/|ftp:\/\//i.test(cur))                    flags2.push('url');
        if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(cur))      flags2.push('ip');
        if (/[a-zA-Z]:\\|\.dll|\.exe|\.bat|\.ps1|\.vbs/i.test(cur)) flags2.push('path');
        results.push({ value: cur, offset: startOff, flags: flags2 });
    }
    return results;
}
function getVSLabel(prodId) {
    if (prodId === 0)  return 'Linker / Import0';
    if (prodId <= 5)   return 'Early MSVC (pre-VS97)';
    if (prodId <= 10)  return 'MSVC 6.0 (VS 1998)';
    if (prodId <= 15)  return 'VS.NET 2002/2003';
    if (prodId >= 0x50  && prodId <= 0x6F) return 'VS 2005';
    if (prodId >= 0x61  && prodId <= 0x7F) return 'VS 2008';
    if (prodId >= 0x80  && prodId <= 0x9F) return 'VS 2010';
    if (prodId >= 0xB0  && prodId <= 0xBF) return 'VS 2012';
    if (prodId >= 0xC0  && prodId <= 0xCF) return 'VS 2013';
    if (prodId >= 0xD0  && prodId <= 0xFF) return 'VS 2015';
    if (prodId >= 0x100 && prodId <= 0x118) return 'VS 2017';
    if (prodId >= 0x119 && prodId <= 0x140) return 'VS 2019';
    if (prodId >= 0x141) return 'VS 2022';
    return 'Compiler 0x' + prodId.toString(16);
}
function parseRichHeader(dv, peOffset) {
    var entries = [];
    try {
        var richPos = -1;
        var scanEnd = Math.min(peOffset, dv.byteLength) - 4;
        for (var i = scanEnd; i >= 0x40; i -= 4) {
            if (dv.getUint32(i, true) === 0x68636952) { richPos = i; break; }
        }
        if (richPos === -1) return entries;

        var xorKey = dv.getUint32(richPos + 4, true);
        var dansPos = -1;
        for (var j = richPos - 4; j >= 0x40; j -= 4) {
            if ((dv.getUint32(j, true) ^ xorKey) === 0x536e6144) { dansPos = j; break; }
        }
        if (dansPos === -1) return entries;
        var dataStart = dansPos + 16;
        for (var k = dataStart; k + 8 <= richPos; k += 8) {
            var raw1   = dv.getUint32(k,     true) ^ xorKey;
            var raw2   = dv.getUint32(k + 4, true) ^ xorKey;
            var buildId = raw1 & 0xFFFF;
            var prodId  = (raw1 >>> 16) & 0xFFFF;
            var count   = raw2;
            entries.push({ prodId: prodId, buildId: buildId, count: count, vsVersion: getVSLabel(prodId) });
        }
    } catch(e) {  }
    return entries;
}
self.onmessage = function(e) {
    var buffer   = e.data.buffer;
    var fileName = e.data.fileName;
    var dv    = new DataView(buffer);
    var bytes = new Uint8Array(buffer);

    try {
        postProgress('reading DOS header...', 5);
        if (dv.byteLength < 64) throw new Error('file too small to be a valid PE.');

        var dosSignature = dv.getUint16(0, true);
        if (dosSignature !== 0x5A4D) throw new Error('missing MZ signature!');

        var peOffset = dv.getUint32(0x3C, true);
        if (peOffset < 0x40 || peOffset + 24 > dv.byteLength)
            throw new Error('PE header offset is invalid!');

        postProgress('verifying PE signature...', 10);
        var peSig = dv.getUint32(peOffset, true);
        if (peSig !== 0x00004550) throw new Error('missing PE signature!');

        var coffOff    = peOffset + 4;
        var machine    = dv.getUint16(coffOff,      true);
        var numSec     = dv.getUint16(coffOff + 2,  true);
        var timestamp  = dv.getUint32(coffOff + 4,  true);
        var optHdrSize = dv.getUint16(coffOff + 16, true);
        var is64       = (machine === 0x8664 || machine === 0xaa64);

        var optOff      = coffOff + 20;
        var secTableOff = optOff + optHdrSize;

        postProgress('parsing optional header + data directories...', 20);
        var ddBase = optOff + (is64 ? 112 : 96);
        var dataDirectories = [];
        for (var di = 0; di < 16; di++) {
            var ddOff = ddBase + di * 8;
            if (ddOff + 8 > dv.byteLength) { dataDirectories.push({ rva: 0, size: 0 }); continue; }
            dataDirectories.push({
                rva:  dv.getUint32(ddOff,     true),
                size: dv.getUint32(ddOff + 4, true),
            });
        }

        postProgress('mapping sections...', 30);

        var sections = [];
        var off = secTableOff;
        for (var si = 0; si < numSec; si++) {
            if (off + 40 > dv.byteLength) break;
            var nameBytes = new Uint8Array(buffer, off, 8);
            var name = new TextDecoder().decode(nameBytes).replace(/\0/g, '');
            sections.push({
                name:              name,
                virtualSize:       dv.getUint32(off + 8,  true),
                virtualAddress:    dv.getUint32(off + 12, true),
                sizeOfRawData:     dv.getUint32(off + 16, true),
                pointerToRawData:  dv.getUint32(off + 20, true),
                characteristics:   dv.getUint32(off + 36, true),
            });
            off += 40;
        }

        postProgress('calculating entropy for each section...', 45);

        var enriched = sections.map(function(sec) {
            var entropy = 0;
            var rawStart = sec.pointerToRawData;
            var rawSize  = sec.sizeOfRawData;
            if (rawSize > 0 && rawStart < bytes.length) {
                var rawEnd = Math.min(rawStart + rawSize, bytes.length);
                entropy = calcEntropy(bytes.subarray(rawStart, rawEnd));
            }
            var isWritable   = (sec.characteristics & 0x80000000) !== 0;
            var isExecutable = (sec.characteristics & 0x20000000) !== 0;
            return Object.assign({}, sec, {
                entropy:       entropy,
                isWx:          isWritable && isExecutable,
                isHighEntropy: entropy > 7.0,
            });
        });

        postProgress('parsing import address table (IAT)...', 60);
        var iatResult = parseIAT(dv, sections, is64, dataDirectories);

        postProgress('extracting printable strings... (this can take a moment!!)', 75);
        var strings = extractStrings(bytes);

        postProgress('parsing rich header (compiler fingerprint)...', 88);
        var richHeader = parseRichHeader(dv, peOffset);

        postProgress('packaging result... almost done!!', 95);

        var archStr = machine === 0x14c  ? 'x86 (32-bit)'
                    : machine === 0x8664 ? 'x64 (64-bit)'
                    : machine === 0x01c4 ? 'ARM (32-bit)'
                    : machine === 0xaa64 ? 'ARM64'
                    : 'Unknown (0x' + machine.toString(16) + ')';
        var hexBytes = Array.from(bytes.subarray(0, Math.min(bytes.length, 65536)));

        self.postMessage({
            type: 'result',
            data: {
                fileName:       fileName,
                fileSize:       bytes.length,
                arch:           archStr,
                is64bit:        is64,
                timeDateStamp:  timestamp,
                sections:       enriched,
                imports:        iatResult.imports,
                apiCategories:  iatResult.apiCategories,
                strings:        strings,
                richHeader:     richHeader,
                hexBytes:       hexBytes,
                dataDirectories: dataDirectories,
            },
        });

    } catch(err) {
        self.postMessage({ type: 'error', message: err.message });
    }
};
