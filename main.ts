import { Hono } from "npm:hono@4";
const app = new Hono();
const kv = await Deno.openKv(); 
app.get("/", async (c) => {
  const links = [];
  for await (const entry of kv.list({ prefix: ["links"] })) {
    links.push(entry.value);
  }
  const activeCount = links.filter(l => l.status === 'active').length;
  return c.html(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Auto File Keeper</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" />
    </head>
    <body class="bg-gray-900 text-gray-200 min-h-screen p-4 flex flex-col items-center">
        <div class="w-full max-w-5xl">
            <!-- Header Info -->
            <div class="flex justify-between items-center mb-6">
                <div>
                    <h1 class="text-2xl font-bold text-emerald-400"><i class="fa-solid fa-cloud-arrow-up mr-2"></i> QyShare Auto Keeper</h1>
                    <p class="text-xs text-gray-400 mt-1">Runs automatically every 2 days</p>
                </div>
                <div class="text-right">
                    <div class="text-3xl font-bold text-white">${links.length}</div>
                    <div class="text-xs text-gray-400">Total Monitored Links</div>
                </div>
            </div>
            <!-- Add New Links Section -->
            <div class="bg-gray-800 p-5 rounded-xl border border-gray-700 shadow-lg mb-8">
                <label class="block text-xs font-bold text-gray-400 mb-2 uppercase">Add New Links (Don't worry, old links remain safe)</label>
                <div class="flex gap-2">
                    <textarea id="newLinks" rows="2" class="w-full bg-gray-900 border border-gray-600 rounded p-3 text-xs text-green-300 focus:outline-none focus:border-emerald-500" placeholder="https://wwwk.qyshare.com:2083/s/...\nPaste new links here..."></textarea>
                    <button onclick="addLinks()" class="bg-emerald-600 hover:bg-emerald-500 text-white px-6 rounded-lg font-bold text-sm whitespace-nowrap">
                        <i class="fa-solid fa-plus mr-1"></i> Add to List
                    </button>
                </div>
            </div>
            <!-- Monitored List -->
            <div class="bg-gray-800 rounded-xl overflow-hidden border border-gray-700 shadow-lg">
                <div class="px-6 py-4 border-b border-gray-700 bg-gray-800/50 flex justify-between items-center">
                    <span class="text-sm font-bold text-gray-300">Monitored List (${activeCount} Active)</span>
                    <button onclick="runCheckNow()" class="text-xs bg-blue-600 hover:bg-blue-500 text-white px-3 py-1 rounded">
                        ⚡ Force Check All Now
                    </button>
                </div>
                <div class="overflow-x-auto max-h-[600px]">
                    <table class="w-full text-left text-xs">
                        <thead class="bg-gray-900 text-gray-500 sticky top-0">
                            <tr>
                                <th class="p-4">Link Info</th>
                                <th class="p-4">Last Checked</th>
                                <th class="p-4">Latest Status</th>
                                <th class="p-4 text-right">Action</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-700">
                            ${links.length === 0 ? '<tr><td colspan="4" class="p-8 text-center text-gray-500">No links yet. Add some above!</td></tr>' : ''}
                            ${links.map(l => `
                                <tr class="hover:bg-gray-700/30 transition">
                                    <td class="p-4">
                                        <div class="text-blue-300 font-mono truncate max-w-[300px]" title="${l.url}">${l.url}</div>
                                        ${l.title ? `<div class="text-[10px] text-gray-500 mt-1">${l.title}</div>` : ''}
                                    </td>
                                    <td class="p-4 text-gray-400">
                                        ${l.last_check ? new Date(l.last_check).toLocaleString() : 'Pending...'}
                                    </td>
                                    <td class="p-4">
                                        ${l.status === 'active' 
                                            ? '<span class="bg-green-900/50 text-green-400 px-2 py-1 rounded border border-green-900">✅ Active</span>' 
                                            : l.status === 'failed' 
                                            ? `<span class="bg-red-900/50 text-red-400 px-2 py-1 rounded border border-red-900" title="${l.error}">❌ Failed</span>`
                                            : '<span class="text-yellow-500">⏳ Waiting</span>'}
                                    </td>
                                    <td class="p-4 text-right">
                                        <button onclick="deleteLink('${l.url}')" class="text-red-400 hover:text-red-300 transition">
                                            <i class="fa-solid fa-trash"></i>
                                        </button>
                                    </td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        <script>
            async function addLinks() {
                const text = document.getElementById('newLinks').value;
                if(!text.trim()) return alert("Please enter links");
                const btn = document.querySelector('button');
                btn.innerText = "Saving..."; btn.disabled = true;
                await fetch('/api/add', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ links: text.split('\\n').map(l=>l.trim()).filter(l=>l) })
                });
                window.location.reload();
            }
            async function deleteLink(url) {
                if(!confirm("Remove this link from monitoring?")) return;
                await fetch('/api/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ url })
                });
                window.location.reload();
            }
            async function runCheckNow() {
                if(!confirm("This will check ALL links immediately. Continue?")) return;
                alert("Process started in background. Page will reload in 3 seconds.");
                fetch('/api/trigger'); 
                setTimeout(() => window.location.reload(), 3000);
            }
        </script>
    </body>
    </html>
  `);
});
app.post("/api/add", async (c) => {
    const { links } = await c.req.json();
    for (const url of links) {
        const existing = await kv.get(["links", url]);
        if (!existing.value) {
            await kv.set(["links", url], {
                url,
                status: "pending",
                added_at: Date.now(),
                last_check: null,
                error: null
            });
        }
    }
    return c.json({ success: true });
});
app.post("/api/delete", async (c) => {
    const { url } = await c.req.json();
    await kv.delete(["links", url]);
    return c.json({ success: true });
});
app.get("/api/trigger", (c) => {
    runMaintenance(); 
    return c.text("Started");
});
Deno.cron("Keep Alive Task", "0 8 */2 * *", async () => {
    console.log("⏰ Scheduled Maintenance Started...");
    await runMaintenance();
});
async function runMaintenance() {
    const allLinks = [];
    for await (const entry of kv.list({ prefix: ["links"] })) {
        allLinks.push(entry.value);
    }
    console.log(`Checking ${allLinks.length} links...`);
    for (const linkData of allLinks) {
        try {
            await processQyShare(linkData.url);
            await kv.set(["links", linkData.url], {
                ...linkData,
                status: "active",
                last_check: Date.now(),
                error: null
            });
        } catch (e) {
            console.error(`Failed ${linkData.url}: ${e.message}`);
            await kv.set(["links", linkData.url], {
                ...linkData,
                status: "failed",
                last_check: Date.now(),
                error: e.message
            });
        }
        await new Promise(r => setTimeout(r, 500)); 
    }
    console.log("Maintenance Complete.");
}
async function processQyShare(url) {
    const res = await fetch(url, { headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0" } });
    if (!res.ok) throw new Error("Page Load Failed");
    const html = await res.text();
    const token = html.match(/const token = "([^"]+)";/)?.[1];
    const fileId = html.match(/const fileId = (\d+);/)?.[1];
    const hostsMatch = html.match(/const downloadHosts = (\[.*?\]);/s);
    if (!token || !fileId || !hostsMatch) throw new Error("Invalid Page Format");
    const hosts = JSON.parse(hostsMatch[1]);
    if (hosts.length === 0) throw new Error("No Hosts Available");
    const apiUrl = `${new URL(url).origin}/api/share/download?token=${encodeURIComponent(token)}&fileId=${encodeURIComponent(fileId)}&hostId=${hosts[0].id}`;
    const apiRes = await fetch(apiUrl, {
        method: 'GET',
        headers: { "User-Agent": "Mozilla/5.0", "Referer": url },
        redirect: "follow"
    });
    if (!apiRes.ok) throw new Error("Download Request Failed");
    await apiRes.body?.cancel();
    return true;
}
Deno.serve(app.fetch);
