import { Hono } from "npm:hono@4";

const app = new Hono();

// --- 1. Frontend UI (Same as before) ---
app.get("/", (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>QyShare Link Extractor</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
        <style>
            body { background-color: #0f172a; color: #e2e8f0; font-family: monospace; }
            .terminal { background: #1e293b; border: 1px solid #334155; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
        </style>
    </head>
    <body class="min-h-screen p-4 flex flex-col items-center">
        <div class="w-full max-w-4xl">
            <h1 class="text-2xl font-bold mb-4 text-emerald-400">
                <i class="fa-solid fa-code mr-2"></i> QyShare JS Extractor
            </h1>

            <div class="terminal rounded-lg p-4 mb-6">
                <label class="block text-xs text-slate-400 mb-2">PASTE LINKS (One per line):</label>
                <textarea id="inputLinks" rows="6" class="w-full bg-slate-900 border border-slate-700 rounded p-3 text-xs focus:border-emerald-500 focus:outline-none text-green-300 placeholder-slate-600" placeholder="https://wwwk.qyshare.com:2083/s/ziugvu"></textarea>
                
                <div class="flex justify-between items-center mt-3">
                    <span id="status" class="text-xs text-slate-400">Ready.</span>
                    <button onclick="startProcess()" id="startBtn" class="bg-emerald-600 hover:bg-emerald-500 text-white px-6 py-2 rounded text-sm font-bold transition">
                        START PROCESS
                    </button>
                </div>
            </div>

            <div class="terminal rounded-lg overflow-hidden">
                <div class="max-h-[500px] overflow-y-auto p-0">
                    <table class="w-full text-left border-collapse">
                        <thead class="bg-slate-900 text-xs text-slate-500 sticky top-0">
                            <tr><th class="p-3">URL</th><th class="p-3">STATUS</th><th class="p-3">DIRECT LINK</th></tr>
                        </thead>
                        <tbody id="resultBody" class="text-xs"></tbody>
                    </table>
                </div>
            </div>
        </div>

        <script>
            async function startProcess() {
                const text = document.getElementById('inputLinks').value;
                if(!text.trim()) return alert("No links!");
                const links = text.split('\\n').map(l => l.trim()).filter(l => l);
                const tbody = document.getElementById('resultBody');
                const status = document.getElementById('status');
                
                tbody.innerHTML = "";

                for (let i = 0; i < links.length; i++) {
                    const url = links[i];
                    status.innerText = \`Processing \${i+1}/\${links.length}...\`;
                    
                    const row = document.createElement('tr');
                    row.className = "border-b border-slate-700";
                    row.innerHTML = \`
                        <td class="p-3 text-blue-300 truncate max-w-[150px]">\${url}</td>
                        <td class="p-3"><span class="text-yellow-500">Processing...</span></td>
                        <td class="p-3 text-slate-500">-</td>
                    \`;
                    tbody.appendChild(row);

                    try {
                        const res = await fetch('/api/check', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({ url })
                        });
                        const data = await res.json();

                        if(data.success) {
                            row.querySelector('td:nth-child(2)').innerHTML = '<span class="text-green-400 font-bold">SUCCESS</span>';
                            row.querySelector('td:nth-child(3)').innerHTML = \`
                                <div class="flex gap-2">
                                    <input value="\${data.directLink}" class="bg-black w-full px-1 text-green-400" readonly>
                                    <button onclick="navigator.clipboard.writeText('\${data.directLink}')">COPY</button>
                                </div>\`;
                        } else {
                            row.querySelector('td:nth-child(2)').innerHTML = '<span class="text-red-400 font-bold">FAILED</span>';
                            row.querySelector('td:nth-child(3)').innerText = data.error;
                        }
                    } catch (e) {
                         row.querySelector('td:nth-child(2)').innerHTML = 'ERROR';
                    }
                }
                status.innerText = "Done!";
            }
        </script>
    </body>
    </html>
  `);
});

// --- 2. The Backend Logic (Reverse Engineering JS) ---
app.post("/api/check", async (c) => {
    try {
        const { url } = await c.req.json();
        if (!url) return c.json({ success: false, error: "No URL" });

        // Step 1: Fetch the HTML Page
        const res = await fetch(url, {
            headers: { 
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" 
            }
        });
        
        if (!res.ok) return c.json({ success: false, error: "Page Load Failed" });
        const html = await res.text();

        // Step 2: Extract JS Variables using Regex
        // HTML ထဲက const token = "xxx"; နဲ့ fileId တို့ကို ဆွဲထုတ်ပါမယ်
        const tokenMatch = html.match(/const token = "([^"]+)";/);
        const fileIdMatch = html.match(/const fileId = (\d+);/);
        const hostsMatch = html.match(/const downloadHosts = (\[.*?\]);/s);

        if (!tokenMatch || !fileIdMatch || !hostsMatch) {
            return c.json({ success: false, error: "Cannot parse JS variables (Tokens not found)" });
        }

        const token = tokenMatch[1];
        const fileId = fileIdMatch[1];
        let hosts = [];
        
        try {
            hosts = JSON.parse(hostsMatch[1]);
        } catch (e) {
            return c.json({ success: false, error: "JSON Parse Error on Hosts" });
        }

        if (hosts.length === 0) return c.json({ success: false, error: "No download hosts available" });

        // Step 3: Pick a Host & Construct API URL
        // မူရင်း JS မှာ ping စစ်ပေမယ့် Server မှာမို့ ပထမဆုံး host (သို့) hostId ကို တန်းယူပါမယ်
        const targetHost = hosts[0]; // First available host
        const hostId = targetHost.id;

        // Origin (e.g., https://wwwk.qyshare.com:2083)
        const origin = new URL(url).origin;
        
        // Final API URL Construction
        const apiUrl = `${origin}/api/share/download?token=${encodeURIComponent(token)}&fileId=${encodeURIComponent(fileId)}&hostId=${encodeURIComponent(hostId)}`;

        // Step 4: Hit the API to get the 302 Redirect (Direct Link)
        const apiRes = await fetch(apiUrl, {
            method: 'GET',
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
                "Referer": url, // Referer မပါရင် Error တက်တတ်ပါတယ်
            },
            redirect: "follow" // Follow redirects to get the final file link
        });

        if (!apiRes.ok) {
            // တစ်ခါတလေ hostId မလိုဘဲ default နဲ့ရတတ်တယ်၊ ပြန်စမ်းကြည့်မယ်
            const fallbackUrl = `${origin}/api/share/download?token=${encodeURIComponent(token)}&fileId=${encodeURIComponent(fileId)}`;
            const fallbackRes = await fetch(fallbackUrl, {
                headers: { "User-Agent": "Mozilla/5.0", "Referer": url },
                redirect: "follow"
            });
            
            if(fallbackRes.ok) {
                return c.json({ success: true, directLink: fallbackRes.url });
            }
            
            return c.json({ success: false, error: "API Request Failed" });
        }

        // Active ဖြစ်အောင် Connection စပြီးရင် ဖြတ်လိုက်မယ်
        // apiRes.url က နောက်ဆုံးရောက်သွားတဲ့ Direct Link (mp4) ပါ
        const directLink = apiRes.url;
        await apiRes.body?.cancel(); 

        return c.json({ 
            success: true, 
            directLink: directLink 
        });

    } catch (e) {
        return c.json({ success: false, error: e.message });
    }
});

Deno.serve(app.fetch);
