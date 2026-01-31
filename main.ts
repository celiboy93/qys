import { Hono } from "npm:hono@4";
import { DOMParser } from "https://deno.land/x/deno_dom/deno-dom-wasm.ts";

const app = new Hono();

// --- 1. The Frontend UI ---
app.get("/", (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bulk Link Checker & Extractor</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
        <style>
            body { background-color: #0f172a; color: #e2e8f0; font-family: monospace; }
            .terminal { background: #1e293b; border: 1px solid #334155; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
            ::-webkit-scrollbar { width: 8px; }
            ::-webkit-scrollbar-thumb { background: #475569; border-radius: 4px; }
        </style>
    </head>
    <body class="min-h-screen p-4 flex flex-col items-center">
        
        <div class="w-full max-w-4xl">
            <h1 class="text-2xl font-bold mb-4 text-emerald-400">
                <i class="fa-solid fa-terminal mr-2"></i> Bulk Link Extractor
            </h1>

            <!-- Input Area -->
            <div class="terminal rounded-lg p-4 mb-6">
                <label class="block text-xs text-slate-400 mb-2">PASTE LINKS (One per line):</label>
                <textarea id="inputLinks" rows="6" class="w-full bg-slate-900 border border-slate-700 rounded p-3 text-xs focus:border-emerald-500 focus:outline-none text-green-300 placeholder-slate-600" placeholder="https://wwwk.qyshare.com/s/...\nhttps://wwwk.qyshare.com/s/..."></textarea>
                
                <div class="flex justify-between items-center mt-3">
                    <span id="status" class="text-xs text-slate-400">Ready to process.</span>
                    <button onclick="startProcess()" id="startBtn" class="bg-emerald-600 hover:bg-emerald-500 text-white px-6 py-2 rounded text-sm font-bold transition">
                        <i class="fa-solid fa-play mr-1"></i> START NOW
                    </button>
                </div>
            </div>

            <!-- Results Table -->
            <div class="terminal rounded-lg overflow-hidden">
                <div class="bg-slate-800 px-4 py-2 border-b border-slate-700 flex justify-between">
                    <span class="text-xs font-bold text-slate-300">RESULTS LOG</span>
                    <button onclick="clearLog()" class="text-xs text-red-400 hover:text-red-300">CLEAR</button>
                </div>
                <div class="max-h-[500px] overflow-y-auto p-0">
                    <table class="w-full text-left border-collapse">
                        <thead class="bg-slate-900 text-xs text-slate-500 sticky top-0">
                            <tr>
                                <th class="p-3 w-10">#</th>
                                <th class="p-3">ORIGINAL URL</th>
                                <th class="p-3 w-24">STATUS</th>
                                <th class="p-3">DIRECT LINK / INFO</th>
                            </tr>
                        </thead>
                        <tbody id="resultBody" class="text-xs">
                            <!-- Results will appear here -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <script>
            async function startProcess() {
                const text = document.getElementById('inputLinks').value;
                if(!text.trim()) return alert("Please paste some links!");

                const links = text.split('\\n').map(l => l.trim()).filter(l => l);
                const tbody = document.getElementById('resultBody');
                const btn = document.getElementById('startBtn');
                const status = document.getElementById('status');

                btn.disabled = true;
                btn.classList.add('opacity-50', 'cursor-not-allowed');
                tbody.innerHTML = ""; // Clear previous

                let successCount = 0;

                for (let i = 0; i < links.length; i++) {
                    const url = links[i];
                    status.innerText = \`Processing \${i+1} of \${links.length}...\`;
                    
                    // Create Row
                    const row = document.createElement('tr');
                    row.className = "border-b border-slate-700 hover:bg-slate-800 transition";
                    row.innerHTML = \`
                        <td class="p-3 text-slate-500">\${i+1}</td>
                        <td class="p-3 text-blue-300 truncate max-w-[200px]" title="\${url}">\${url}</td>
                        <td class="p-3"><i class="fa-solid fa-circle-notch fa-spin text-yellow-500"></i></td>
                        <td class="p-3 text-slate-500">Processing...</td>
                    \`;
                    tbody.appendChild(row);
                    row.scrollIntoView({ behavior: 'smooth', block: 'end' });

                    try {
                        // Call Backend API
                        const res = await fetch('/api/check', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({ url })
                        });
                        const data = await res.json();

                        // Update Row based on result
                        if(data.success) {
                            successCount++;
                            row.querySelector('td:nth-child(3)').innerHTML = '<span class="bg-green-900 text-green-300 px-2 py-1 rounded text-[10px] font-bold">SUCCESS</span>';
                            
                            // Show Direct Link with Copy Button
                            const directLink = data.directLink || "N/A";
                            row.querySelector('td:nth-child(4)').innerHTML = \`
                                <div class="flex items-center gap-2">
                                    <input type="text" value="\${directLink}" class="bg-black border border-slate-600 rounded px-2 py-1 w-full text-green-400 font-mono text-[10px]" readonly>
                                    <button onclick="navigator.clipboard.writeText('\${directLink}')" class="text-slate-400 hover:text-white"><i class="fa-regular fa-copy"></i></button>
                                </div>
                            \`;
                        } else {
                            row.querySelector('td:nth-child(3)').innerHTML = '<span class="bg-red-900 text-red-300 px-2 py-1 rounded text-[10px] font-bold">FAILED</span>';
                            row.querySelector('td:nth-child(4)').innerText = data.error || "Unknown Error";
                            row.querySelector('td:nth-child(4)').classList.add('text-red-400');
                        }

                    } catch (e) {
                         row.querySelector('td:nth-child(3)').innerHTML = '<span class="bg-red-900 text-red-300 px-2 py-1 rounded text-[10px] font-bold">ERROR</span>';
                         row.querySelector('td:nth-child(4)').innerText = "Network Error";
                    }
                }

                status.innerText = \`Completed! (\${successCount}/\${links.length} Success)\`;
                btn.disabled = false;
                btn.classList.remove('opacity-50', 'cursor-not-allowed');
            }

            function clearLog() { document.getElementById('resultBody').innerHTML = ""; }
        </script>
    </body>
    </html>
  `);
});

// --- 2. The Backend Processor API ---
app.post("/api/check", async (c) => {
    try {
        const { url } = await c.req.json();
        if (!url) return c.json({ success: false, error: "No URL" });

        // Step 1: Visit Page
        const res = await fetch(url, {
            headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0" }
        });
        
        if (!res.ok) return c.json({ success: false, error: `Page Error (${res.status})` });
        
        const html = await res.text();
        const doc = new DOMParser().parseFromString(html, "text/html");

        // Step 2: Find Form
        // Generic search for forms containing 'download'
        const forms = doc.querySelectorAll("form");
        let targetForm = null;

        for (const f of forms) {
            if (f.innerHTML.toLowerCase().includes("download") || 
                f.getAttribute("id")?.includes("download")) {
                targetForm = f;
                break;
            }
        }
        if (!targetForm && forms.length > 0) targetForm = forms[0]; // Fallback

        if (!targetForm) return c.json({ success: false, error: "No Download Form Found" });

        // Step 3: Extract Data
        const formData = new URLSearchParams();
        targetForm.querySelectorAll("input").forEach((inp: any) => {
             formData.append(inp.getAttribute("name"), inp.getAttribute("value") || "");
        });

        // Resolve Action URL
        let action = targetForm.getAttribute("action");
        if (!action || action === "#") action = url;
        else if (action.startsWith("/")) action = new URL(url).origin + action;

        // Step 4: Submit Form (Fake Click)
        const postRes = await fetch(action, {
            method: targetForm.getAttribute("method") || "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                "Referer": url
            },
            body: formData.toString(),
            redirect: "follow" // Follow the redirect to get final link
        });

        if (!postRes.ok) return c.json({ success: false, error: "Download Request Failed" });

        // Step 5: Get Final URL (Direct Link)
        // If the server redirects to the file (e.g. .mp4), postRes.url is the direct link
        const finalUrl = postRes.url;
        
        // Active Count စာရင်းဝင်သွားပါပြီ (Abort to save bandwidth)
        // We only need the URL/Headers
        await postRes.body?.cancel();

        return c.json({ 
            success: true, 
            directLink: finalUrl 
        });

    } catch (e) {
        return c.json({ success: false, error: e.message });
    }
});

Deno.serve(app.fetch);
