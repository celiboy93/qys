// main.ts
const envUUID = Deno.env.get('UUID') || crypto.randomUUID();
const subPath = Deno.env.get('SUB_PATH') || envUUID;
const password = Deno.env.get('PASSWORD') || '';
const proxyIP = Deno.env.get('PROXYIP') || '';

// မျှော်လင့်ထားသော CDN IP များ
const cfip = [
    'mfa.gov.ua#SG', 'saas.sin.fan#HK', 'store.ubi.com#JP','cf.130519.xyz#KR','cf.008500.xyz#HK', 
    'cf.090227.xyz#SG', 'cf.877774.xyz#HK','cdns.doon.eu.org#JP','sub.danfeng.eu.org#TW','cf.zhetengsha.eu.org#HK'
];

console.log(`UUID: ${envUUID}`);
console.log(`SubPath: /${subPath}`);

Deno.serve(async (request: Request) => {
    const upgrade = request.headers.get('upgrade') || '';
    if (upgrade.toLowerCase() === 'websocket') {
        return await vlessOverWSHandler(request);
    }

    const url = new URL(request.url);
    const baseUrl = `${url.protocol}//${url.host}`;
    
    if (request.method === 'GET') {
        // Subscription လမ်းကြောင်း
        if (url.pathname.toLowerCase() === `/${subPath.toLowerCase()}`) {
            const currentDomain = url.hostname;
            const vlsHeader = 'vless';
            
            const vlsLinks = cfip.map(cdnItem => {
                let host, port = 443, nodeName = '';
                if (cdnItem.includes('#')) {
                    const parts = cdnItem.split('#');
                    cdnItem = parts[0];
                    nodeName = parts[1];
                }
                if (cdnItem.includes(':') && !cdnItem.startsWith('[')) {
                    const parts = cdnItem.split(':');
                    host = parts[0];
                    port = parseInt(parts[1]) || 443;
                } else {
                    host = cdnItem;
                }
                
                const vlsNodeName = nodeName ? `${nodeName}-${vlsHeader}` : `Deno-${vlsHeader}`;
                return `${vlsHeader}://${envUUID}@${host}:${port}?encryption=none&security=tls&sni=${currentDomain}&fp=firefox&type=ws&host=${currentDomain}&path=%2F%3Fed%3D2560#${vlsNodeName}`;
            });
            
            const base64Content = btoa(unescape(encodeURIComponent(vlsLinks.join('\n'))));
            return new Response(base64Content, {
                headers: { 
                    'Content-Type': 'text/plain; charset=utf-8',
                    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                },
            });
        }

        // မူလစာမျက်နှာ (Home & Login)
        if (url.pathname === '/') {
            const providedPassword = url.searchParams.get('password');
            if (password !== '' && providedPassword !== password) {
                return getLoginPage(url.hostname, baseUrl, !!providedPassword);
            }
            return getMainPageContent(url.hostname, baseUrl);
        }
    }

    return new Response('Not Found', { status: 404 });
});

async function vlessOverWSHandler(request: Request) {
    const { socket, response } = Deno.upgradeWebSocket(request);
    let earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    
    socket.onopen = () => {
        // Early data handling can be implemented here if needed
    };

    socket.onmessage = async (event) => {
        const vlessBuffer = event.data as ArrayBuffer;
        if (vlessBuffer.byteLength < 24) return;
        
        const version = new Uint8Array(vlessBuffer.slice(0, 1));
        const incomingUUID = stringify(new Uint8Array(vlessBuffer.slice(1, 17)));
        
        if (incomingUUID !== envUUID) {
            socket.close();
            return;
        }

        const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
        const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 19 + optLength))[0];
        
        // 1 = TCP, 2 = UDP
        if (command !== 1 && command !== 2) {
            socket.close();
            return;
        }

        const portIndex = 19 + optLength;
        const portRemote = new DataView(vlessBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

        let addressIndex = portIndex + 2;
        const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];
        let addressLength = 0;
        let addressValueIndex = addressIndex + 1;
        let addressValue = '';

        if (addressType === 1) {
            addressLength = 4;
            addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
        } else if (addressType === 2) {
            addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        } else if (addressType === 3) {
            addressLength = 16;
            const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(':');
        }

        const rawDataIndex = addressValueIndex + addressLength;
        const rawClientData = new Uint8Array(vlessBuffer.slice(rawDataIndex));
        const vlessResponseHeader = new Uint8Array([version[0], 0]);

        try {
            // Use proxyIP if set, else direct target
            const targetAddress = proxyIP ? proxyIP.split(':')[0] : addressValue;
            const targetPort = proxyIP && proxyIP.includes(':') ? parseInt(proxyIP.split(':')[1]) : portRemote;

            const tcpSocket = await Deno.connect({ hostname: targetAddress, port: targetPort });
            
            // Send initial data
            if (rawClientData.length > 0) {
                const writer = tcpSocket.writable.getWriter();
                await writer.write(rawClientData);
                writer.releaseLock();
            }

            // Remote to WS
            remoteSocketToWS(tcpSocket, socket, vlessResponseHeader);

            // WS to Remote
            socket.onmessage = async (e) => {
                const writer = tcpSocket.writable.getWriter();
                await writer.write(new Uint8Array(e.data));
                writer.releaseLock();
            };

            socket.onclose = () => {
                tcpSocket.close();
            };
            
        } catch (err) {
            socket.close();
        }
    };

    return response;
}

async function remoteSocketToWS(remoteSocket: Deno.TcpConn, webSocket: WebSocket, vlessResponseHeader: Uint8Array | null) {
    try {
        await remoteSocket.readable.pipeTo(new WritableStream({
            write(chunk) {
                if (webSocket.readyState === WebSocket.OPEN) {
                    if (vlessResponseHeader) {
                        const merged = new Uint8Array(vlessResponseHeader.length + chunk.length);
                        merged.set(vlessResponseHeader);
                        merged.set(chunk, vlessResponseHeader.length);
                        webSocket.send(merged);
                        vlessResponseHeader = null;
                    } else {
                        webSocket.send(chunk);
                    }
                }
            }
        }));
    } catch (e) {
        if (webSocket.readyState === WebSocket.OPEN) webSocket.close();
    }
}

function stringify(arr: Uint8Array) {
    const hex = [...arr].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`;
}

// ================= UI ပိုင်း ================= 
function getLoginPage(url: string, baseUrl: string, showError: boolean) {
    const html = `<!DOCTYPE html>
<html lang="my">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deno Proxy - လော့ဂ်အင်</title>
    <style>
        body { font-family: sans-serif; background: linear-gradient(135deg, #7dd3ca 0%, #a17ec4 100%); height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { background: white; padding: 40px; border-radius: 20px; text-align: center; box-shadow: 0 20px 40px rgba(0,0,0,0.1); }
        input { padding: 10px; width: 80%; margin-bottom: 20px; border: 1px solid #ccc; border-radius: 5px; }
        button { padding: 10px 20px; background: #12cd9e; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .error { color: red; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Deno Service</h2>
        ${showError ? '<div class="error">စကားဝှက်မှားနေပါတယ်</div>' : ''}
        <form onsubmit="handleLogin(event)">
            <input type="password" id="password" placeholder="စကားဝှက်ထည့်ပါ" required autofocus>
            <br>
            <button type="submit">ဝင်မည်</button>
        </form>
    </div>
    <script>
        function handleLogin(event) {
            event.preventDefault();
            const pwd = document.getElementById('password').value;
            window.location.href = '/?password=' + encodeURIComponent(pwd);
        }
    </script>
</body>
</html>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}

function getMainPageContent(url: string, baseUrl: string) {
    const html = `<!DOCTYPE html>
<html lang="my">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deno VLESS Proxy</title>
    <style>
        body { font-family: sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 600px; width: 90%; text-align: center; }
        .info { background: #e9ecef; padding: 15px; border-radius: 5px; text-align: left; margin: 20px 0; font-family: monospace; word-break: break-all; }
        .btn { display: inline-block; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 5px; cursor: pointer; border: none; }
        .btn:hover { background: #0056b3; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Deno Proxy အသင့်ဖြစ်ပါပြီ</h1>
        <div class="info">
            <p><strong>Host:</strong> ${url}</p>
            <p><strong>UUID:</strong> ${envUUID}</p>
            <p><strong>Sub Path:</strong> ${baseUrl}/${subPath}</p>
        </div>
        
        <button class="btn" onclick="copyText('${baseUrl}/${subPath}')">v2rayN / Clash Subscription ကူးမည်</button>
        
        <div style="margin-top: 20px; font-size: 0.9em; color: #666;">
            <a href="javascript:void(0)" onclick="logout()" style="color: red;">အကောင့်ထွက်မည်</a>
        </div>
    </div>
    <script>
        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => alert('လင့်ခ်ကို ကော်ပီကူးပြီးပါပြီ!'));
        }
        function logout() {
            window.location.href = '/';
        }
    </script>
</body>
</html>`;
    return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
}
