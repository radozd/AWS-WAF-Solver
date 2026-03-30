const fs = require('fs');
const vm = require('vm');

const scriptPath = process.argv[2];
if (!scriptPath) {
    console.error(JSON.stringify({ error: 'Usage: node extract_config.js <challenge.js_path>' }));
    process.exit(1);
}

let script;
try {
    script = fs.readFileSync(scriptPath, 'utf-8');
} catch (e) {
    console.error(JSON.stringify({ error: 'Failed to read script: ' + e.message }));
    process.exit(1);
}

try {
    const config = extractConfig(script);
    process.stdout.write(JSON.stringify(config));
} catch (e) {
    console.error(JSON.stringify({ error: 'Extraction failed: ' + e.message }));
    process.exit(1);
}

function extractConfig(script) {
    const arrayNameMatch = script.match(/function\s+(a0_0x[0-9a-f]+)\s*\(\)\s*\{(?:var|let|const)\s+_0x[0-9a-f]+=\[/);
    if (!arrayNameMatch) {
        throw new Error('Could not find global string array function');
    }
    const arrayFuncName = arrayNameMatch[1];

    const decoderNameRe = new RegExp(
        'function\\s+(a0_0x[0-9a-f]+)\\s*\\(\\s*_0x[0-9a-f]+\\s*,\\s*_0x[0-9a-f]+\\s*\\)'
    );
    const decoderNameMatch = script.match(decoderNameRe);
    if (!decoderNameMatch) {
        throw new Error('Could not find decoder function');
    }
    const decoderFuncName = decoderNameMatch[1];

    const arrayFuncCode = extractFunctionAt(script, script.indexOf(arrayNameMatch[0]));
    if (!arrayFuncCode) throw new Error('Failed to extract array function body');

    const decoderFuncStartIdx = script.indexOf(decoderNameMatch[0]);
    const decoderFuncCode = extractFunctionAt(script, decoderFuncStartIdx);
    if (!decoderFuncCode) throw new Error('Failed to extract decoder function body');

    const rotationRe = new RegExp(
        '\\(function\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*\\)\\s*\\{' +
        '[\\s\\S]*?push[\\s\\S]*?shift[\\s\\S]*?' +
        '\\}\\)\\s*\\(\\s*' + arrayFuncName + '\\s*,\\s*0x[0-9a-f]+\\s*\\)\\s*;?'
    );
    const rotationMatch = script.match(rotationRe);

    let setupCode = arrayFuncCode + ';\n';
    setupCode += decoderFuncCode + ';\n';
    if (rotationMatch) {
        setupCode += rotationMatch[0] + ';\n';
    }
    setupCode += `\nthis.__decoder = ${decoderFuncName};\n`;
    setupCode += `this.__decoderName = "${decoderFuncName}";\n`;

    const sandbox = {};
    vm.createContext(sandbox);
    try {
        vm.runInContext(setupCode, sandbox, { timeout: 10000 });
    } catch (e) {
        throw new Error('Failed to eval decoder: ' + e.message);
    }

    const decoder = sandbox.__decoder;
    if (typeof decoder !== 'function') {
        throw new Error('Decoder is not a function after eval');
    }

    const decoded = new Map();
    for (let i = 0; i < 0x600; i++) {
        try {
            const val = decoder(i);
            if (typeof val === 'string' && val.length > 0) {
                decoded.set(i, val);
            }
        } catch (e) {}
    }

    let aesKey = null;
    let aesKeyIdx = -1;
    for (const [idx, val] of decoded) {
        if (/^[0-9a-f]{64}$/.test(val)) {
            aesKey = val;
            aesKeyIdx = idx;
            break;
        }
    }

    let identifier = null;

    const idAssignRe = /\['identifier'\]\s*=\s*(\w+)\s*\(\s*0x([0-9a-f]+)/;
    const idAssignMatch = script.match(idAssignRe);
    if (idAssignMatch) {
        const idIdx = parseInt(idAssignMatch[2], 16);
        const directVal = decoded.get(idIdx);
        if (directVal && /^[A-Za-z]/.test(directVal)) {
            identifier = directVal;
        }
    }

    if (!identifier) {
        const aliasRe = new RegExp(
            '(?:var|let|const)\\s+(\\w+)\\s*=\\s*' + decoderFuncName + '\\b', 'g'
        );
        let aliasMatch;
        const aliases = new Set();
        while ((aliasMatch = aliasRe.exec(script)) !== null) {
            aliases.add(aliasMatch[1]);
        }

        for (const alias of aliases) {
            const re = new RegExp(
                "\\['identifier'\\]\\s*=\\s*" +
                alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') +
                "\\s*\\(\\s*0x([0-9a-f]+)"
            );
            const m = script.match(re);
            if (m) {
                const idx = parseInt(m[1], 16);
                const val = decoded.get(idx);
                if (val && typeof val === 'string') {
                    identifier = val;
                    break;
                }
            }
        }
    }

    if (!identifier) {
        let presentIdx = -1;
        for (const [idx, val] of decoded) {
            if (val === 'Present') { presentIdx = idx; break; }
        }
        if (presentIdx >= 0) {
            const jsBuiltins = new Set([
                'Present', 'Browser', 'String', 'Count', 'Milliseconds', 'Object',
                'Array', 'Function', 'Error', 'Number', 'Boolean', 'RegExp', 'Date',
                'Symbol', 'Promise', 'Proxy', 'Map', 'Set', 'Uint8Array', 'ArrayBuffer',
                'TypeError', 'RangeError', 'SyntaxError', 'UNIVERSAL', 'SEQUENCE',
                'INTEGER', 'OCTET', 'BOOLEAN'
            ]);
            for (let offset = -20; offset <= 0; offset++) {
                const val = decoded.get(presentIdx + offset);
                if (val && /^[A-Z][a-z]{1,15}$/.test(val) && !jsBuiltins.has(val)) {
                    identifier = val;
                    break;
                }
            }
        }
    }

    const typeNames = {};

    const knownTypeNames = new Set(['verify', 'mp_verify', 'captcha', 'interstitial']);
    const typeNameIndices = [];
    for (const [idx, val] of decoded) {
        if (knownTypeNames.has(val)) {
            typeNameIndices.push({ idx, name: val });
        }
    }

    const hashRe = /['"]h([0-9a-f]{60,})['\"]/g;
    let hashMatch;
    const hashes = [];
    while ((hashMatch = hashRe.exec(script)) !== null) {
        hashes.push('h' + hashMatch[1]);
    }

    for (const hash of hashes) {
        if (hash.startsWith('ha9faaffd')) {
            typeNames[hash] = 'mp_verify';
        } else if (hash.startsWith('h72f957df')) {
            typeNames[hash] = 'verify';
        } else if (hash.startsWith('h7b0c470f')) {
            typeNames[hash] = 'verify';
        }
    }

    if (typeNameIndices.length > 0 && hashes.length > typeNames.size) {
        for (const hash of hashes) {
            if (!typeNames[hash]) {
                typeNames[hash] = 'mp_verify';
            }
        }
    }

    let signalVersion = null;
    for (const [idx, val] of decoded) {
        if (/^\d+\.\d+\.\d+$/.test(val) && val !== '0.1.0') {
            signalVersion = val;
            break;
        }
    }
    if (!signalVersion) {
        const versionLiterals = [];
        const versionLitRe = /['"](\\d+\\.\\d+\\.\\d+)['\"]/g;
        let vMatch;
        while ((vMatch = versionLitRe.exec(script)) !== null) {
            if (vMatch[1] !== '0.1.0') {
                versionLiterals.push(vMatch[1]);
            }
        }
        if (versionLiterals.length > 0) {
            signalVersion = versionLiterals[0];
        }
    }

    const allStrings = {};
    for (const [idx, val] of decoded) {
        allStrings['0x' + idx.toString(16)] = val;
    }

    return {
        key: aesKey,
        identifier: identifier,
        typeNames: typeNames,
        signalVersion: signalVersion,
        hashesFound: hashes.length,
        decodedCount: decoded.size,
    };
}

function extractFunctionAt(script, startPos) {
    let braceStart = script.indexOf('{', startPos);
    if (braceStart === -1) return null;

    let depth = 0;
    let inString = false;
    let stringChar = '';
    let escaped = false;

    for (let i = braceStart; i < script.length; i++) {
        const ch = script[i];

        if (escaped) {
            escaped = false;
            continue;
        }

        if (ch === '\\') {
            escaped = true;
            continue;
        }

        if (inString) {
            if (ch === stringChar) inString = false;
            continue;
        }

        if (ch === '"' || ch === '\'' || ch === '`') {
            inString = true;
            stringChar = ch;
            continue;
        }

        if (ch === '/' && i + 1 < script.length) {
            if (script[i + 1] === '/') {
                while (i < script.length && script[i] !== '\n') i++;
                continue;
            }
            if (script[i + 1] === '*') {
                i += 2;
                while (i + 1 < script.length && !(script[i] === '*' && script[i + 1] === '/')) i++;
                i++;
                continue;
            }
        }

        if (ch === '{') depth++;
        if (ch === '}') {
            depth--;
            if (depth === 0) {
                return script.substring(startPos, i + 1);
            }
        }
    }
    return null;
}
