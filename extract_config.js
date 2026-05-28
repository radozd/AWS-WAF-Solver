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

    const rotationMatch = findArrayRotation(script, arrayFuncName);

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

    const idAssignRe = /(?:\['identifier'\]|[\{,]\s*['"]identifier['"]\s*:)\s*=*\s*(\w+)\s*\(\s*0x([0-9a-f]+)/;
    const idAssignMatch = script.match(idAssignRe);
    if (idAssignMatch) {
        const idIdx = parseInt(idAssignMatch[2], 16);
        const directVal = decoded.get(idIdx);
        if (directVal && /^[A-Za-z]/.test(directVal)) {
            identifier = directVal;
        }
    }

    if (!identifier) {
        const idObjectRe = new RegExp(
            "(?:[\\{,]\\s*['\"]identifier['\"]\\s*:|\\['identifier'\\]\\s*=)\\s*" +
            decoderFuncName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') +
            "\\s*\\(\\s*0x([0-9a-f]+)",
            'g'
        );
        let idObjectMatch;
        while ((idObjectMatch = idObjectRe.exec(script)) !== null) {
            const idx = parseInt(idObjectMatch[1], 16);
            const val = decoded.get(idx);
            if (val && /^[A-Za-z]/.test(val)) {
                identifier = val;
                break;
            }
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


    let material = null;
    const materialRe = /['"]material['"]\s*:\s*\[([^\]]+)\]/;
    const materialMatch = script.match(materialRe);
    if (materialMatch) {
        const nums = [];
        const numRe = /0x[0-9a-f]+|\d+/ig;
        let nm;
        while ((nm = numRe.exec(materialMatch[1])) !== null) {
            nums.push(Number(nm[0]));
        }
        if (nums.length > 0) material = nums;
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
    const seenHashes = new Set();
    function addHash(hash) {
        if (typeof hash !== 'string') return;
        if (!/^h[0-9a-f]{40,}$/i.test(hash)) return;
        hash = hash.toLowerCase();
        if (!seenHashes.has(hash)) {
            seenHashes.add(hash);
            hashes.push(hash);
        }
    }
    while ((hashMatch = hashRe.exec(script)) !== null) {
        addHash('h' + hashMatch[1]);
    }

    // Recover assignments where hashes are assembled as string concatenations:
    // obj['ha9faaffd3' + helper(...) + '...'] = 'mp_verify'.
    const recoveredTypeAssignments = recoverTypeNameAssignments(script, setupCode);
    for (const item of recoveredTypeAssignments) {
        addHash(item.hash);
        typeNames[item.hash.toLowerCase()] = item.name;
    }

    for (const hash of hashes) {
        if (typeNames[hash]) continue;
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
        const versionLitRe = /['"](\d+\.\d+\.\d+)['"]/g;
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
        material: material,
        hashesFound: hashes.length,
        decodedCount: decoded.size,
    };
}



function findArrayRotation(script, arrayFuncName) {
    // Avoid catastrophic regexes on large single-line bundles. Most current
    // challenge bundles do not rotate the top-level string table; when they do,
    // the IIFE call is usually close to the array function name.
    const callNeedle = arrayFuncName + ',';
    let pos = 0;
    while ((pos = script.indexOf(callNeedle, pos)) !== -1) {
        const windowStart = Math.max(0, pos - 20000);
        const chunk = script.slice(windowStart, Math.min(script.length, pos + 200));
        if (chunk.includes('push') && chunk.includes('shift')) {
            const startRel = chunk.lastIndexOf('(function');
            if (startRel >= 0) {
                const start = windowStart + startRel;
                const endSemi = script.indexOf(';', pos);
                if (endSemi > start && endSemi - start < 25000) {
                    return [script.slice(start, endSemi + 1)];
                }
            }
        }
        pos += callNeedle.length;
    }
    return null;
}

function recoverTypeNameAssignments(script, baseSetupCode) {
    const out = [];
    const seen = new Set();
    const typeLiteralRe = /['"](verify|mp_verify|captcha|interstitial)['"]/g;
    let m;
    while ((m = typeLiteralRe.exec(script)) !== null) {
        const name = m[1];
        const eq = findPreviousNonSpace(script, m.index - 1);
        if (eq < 0 || script[eq] !== '=') continue;
        const closeBracket = findPreviousNonSpace(script, eq - 1);
        if (closeBracket < 0 || script[closeBracket] !== ']') continue;
        // In these bundles the property expression does not itself contain [];
        // using lastIndexOf avoids the fragile reverse string parser.
        const openBracket = script.lastIndexOf('[', closeBracket);
        if (openBracket < 0 || closeBracket - openBracket > 1000) continue;
        const expr = script.slice(openBracket + 1, closeBracket);
        const hash = evaluateStringExpression(script, baseSetupCode, expr);
        if (hash && /^h[0-9a-f]{40,}$/i.test(hash)) {
            const key = hash.toLowerCase() + ':' + name;
            if (!seen.has(key)) {
                seen.add(key);
                out.push({ hash: hash.toLowerCase(), name });
            }
        }
    }
    return out;
}

function findPreviousNonSpace(str, pos) {
    for (let i = pos; i >= 0; i--) {
        if (!/\s/.test(str[i])) return i;
    }
    return -1;
}

function findMatchingOpenBracket(str, closeIdx) {
    let depth = 0;
    let inString = false;
    let quote = '';
    let escaped = false;
    for (let i = closeIdx; i >= 0; i--) {
        const ch = str[i];
        if (escaped) { escaped = false; continue; }
        if (ch === '\\') { escaped = true; continue; }
        if (inString) {
            if (ch === quote) inString = false;
            continue;
        }
        if (ch === '"' || ch === "'" || ch === '`') {
            inString = true;
            quote = ch;
            continue;
        }
        if (ch === ']') depth++;
        if (ch === '[') {
            depth--;
            if (depth === 0) return i;
        }
    }
    return -1;
}

function evaluateStringExpression(script, baseSetupCode, expr) {
    if (!/^[\s\w$+\-(),.'"`xXa-fA-F0-9]+$/.test(expr)) return null;

    const literalOnly = evaluateLiteralConcat(expr);
    if (literalOnly && /^h[0-9a-f]{40,}$/i.test(literalOnly)) return literalOnly;

    const helperCode = collectHelperCode(script, expr);
    const aliases = collectSimpleAliases(script);
    const sandbox = {};
    vm.createContext(sandbox);
    try {
        vm.runInContext(baseSetupCode + '\n' + aliases + '\n' + helperCode, sandbox, { timeout: 10000 });
        const val = vm.runInContext('(' + expr + ')', sandbox, { timeout: 2000 });
        return typeof val === 'string' ? val : null;
    } catch (e) {
        return null;
    }
}

function evaluateLiteralConcat(expr) {
    const parts = [];
    let pos = 0;
    const tokenRe = /\s*(['"])(.*?)\1\s*(?:\+|$)/gy;
    let m;
    while ((m = tokenRe.exec(expr)) !== null) {
        if (m.index !== pos) return null;
        parts.push(m[2]);
        pos = tokenRe.lastIndex;
        if (pos >= expr.length) break;
    }
    if (pos !== expr.length) return null;
    return parts.join('');
}

function collectSimpleAliases(script) {
    const lines = [];
    const aliasRe = /(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*[;,]/g;
    let m;
    const seen = new Set();
    while ((m = aliasRe.exec(script)) !== null) {
        if (!/^a0_0x[0-9a-f]+$/i.test(m[2])) continue;
        const line = 'var ' + m[1] + ' = ' + m[2] + ';';
        if (!seen.has(line)) {
            seen.add(line);
            lines.push(line);
        }
    }
    return lines.join('\n');
}

function collectHelperCode(script, expr) {
    const needed = new Set();
    const emitted = new Set();
    const chunks = [];
    addNamesFromText(expr, needed);

    for (let round = 0; round < 6; round++) {
        let changed = false;
        for (const name of Array.from(needed)) {
            if (emitted.has(name)) continue;
            const idx = script.indexOf('function ' + name);
            if (idx < 0) continue;
            const code = extractFunctionAt(script, idx);
            if (!code) continue;
            emitted.add(name);
            chunks.push(code + ';');
            addNamesFromText(code, needed);
            changed = true;
        }
        if (!changed) break;
    }
    const rotationCode = collectArrayRotations(script, Array.from(emitted));
    if (rotationCode) chunks.push(rotationCode);
    return chunks.join('\n');
}

function collectArrayRotations(script, names) {
    const chunks = [];
    const seen = new Set();
    for (const name of names) {
        let pos = 0;
        const needle = '(' + name + ');';
        while ((pos = script.indexOf(needle, pos)) !== -1) {
            const startBang = script.lastIndexOf('!function', pos);
            const startParen = script.lastIndexOf('(function', pos);
            let start = Math.max(startBang, startParen);
            if (start >= 0 && pos - start < 5000) {
                const end = pos + needle.length;
                const code = script.slice(start, end);
                if ((code.includes('shift') || code.includes('push')) && !seen.has(code)) {
                    seen.add(code);
                    chunks.push(code + ';');
                }
            }
            pos += needle.length;
        }
    }
    return chunks.join('\n');
}

function addNamesFromText(text, set) {
    const callRe = /\b([A-Za-z_$][\w$]*)\s*\(/g;
    let m;
    while ((m = callRe.exec(text)) !== null) {
        const name = m[1];
        if (/^(function|if|for|while|switch|catch|return|parseInt|String|Number|Boolean|Object|Array|Promise|Date|decodeURIComponent)$/.test(name)) continue;
        if (/^(a0_0x|_0x)[0-9a-f]+$/i.test(name)) set.add(name);
    }
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
