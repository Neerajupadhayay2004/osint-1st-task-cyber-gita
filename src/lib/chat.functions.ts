import { createServerFn } from "@tanstack/react-start";

export type ChatMsg = { role: "user" | "assistant" | "system"; content: string };

const SYSTEM_PROMPT = `You are CyberGita AI — an elite OSINT & cybersecurity analyst assistant inside the CyberGita platform.

You help with:
- Threat intelligence (CVEs, exploits, IOCs, APT groups, malware families)
- IP / domain / email / hash analysis and triage
- Interpreting Shodan, VirusTotal, AbuseIPDB, NVD, KEV results
- Recon strategies (DNS, subdomains, OSINT footprinting)
- Incident response checklists, hardening, MITRE ATT&CK mapping
- Explaining vulnerabilities (with CVSS, CWE, remediation)

Style:
- Be concise, technical, and actionable. Use markdown: bold, lists, code blocks.
- When a user pastes an indicator (IP/domain/hash/email/CVE), suggest which CyberGita module to run (e.g. /ip-domain, /shodan, /virustotal, /cve-search).
- When uncertain, say so. Never invent CVE numbers or breach data.
- Refuse offensive operational guidance against systems the user does not own.`;

async function callGateway(messages: ChatMsg[], model: string) {
  const key = process.env.LOVABLE_API_KEY;
  if (!key) return { ok: false as const, error: "LOVABLE_API_KEY missing", status: 500 };
  const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
    body: JSON.stringify({ model, messages, temperature: 0.4 }),
  });
  const j: any = await r.json().catch(() => ({}));
  if (!r.ok) return { ok: false as const, error: j?.error?.message || `HTTP ${r.status}`, status: r.status };
  const text = j?.choices?.[0]?.message?.content || "";
  return { ok: true as const, text, model };
}

async function callGeminiDirect(messages: ChatMsg[]) {
  const key = process.env.GEMINI_API_KEY;
  if (!key) return { ok: false as const, error: "GEMINI_API_KEY missing", status: 500 };
  const sys = messages.find((m) => m.role === "system")?.content;
  const contents = messages
    .filter((m) => m.role !== "system")
    .map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }));
  const body: any = { contents, generationConfig: { temperature: 0.4, maxOutputTokens: 4096 } };
  if (sys) body.systemInstruction = { parts: [{ text: sys }] };
  const r = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${key}`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) },
  );
  const j: any = await r.json().catch(() => ({}));
  if (!r.ok) return { ok: false as const, error: j?.error?.message || `HTTP ${r.status}`, status: r.status };
  const text = j?.candidates?.[0]?.content?.parts?.map((p: any) => p.text).join("") || "";
  return { ok: true as const, text, model: "gemini-2.0-flash (direct)" };
}

export const chatSend = createServerFn({ method: "POST" })
  .inputValidator((d: { messages: ChatMsg[] }) => d)
  .handler(async ({ data }) => {
    const msgs: ChatMsg[] = [{ role: "system", content: SYSTEM_PROMPT }, ...data.messages.slice(-30)];
    const tryModels = ["google/gemini-2.5-flash", "google/gemini-2.5-flash-lite", "google/gemini-2.0-flash-lite"];
    let lastErr = "";
    for (const m of tryModels) {
      const res = await callGateway(msgs, m);
      if (res.ok) return { ok: true, text: res.text, model: res.model };
      lastErr = res.error;
      if (res.status !== 429 && res.status !== 402 && res.status !== 503) break;
    }
    // Fallback to direct Gemini API key
    const direct = await callGeminiDirect(msgs);
    if (direct.ok) return { ok: true, text: direct.text, model: direct.model };
    return { ok: false, error: `Gateway: ${lastErr} | Direct: ${direct.error}` };
  });
