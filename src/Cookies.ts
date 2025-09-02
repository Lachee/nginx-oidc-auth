import type { IncomingMessage } from "http";

/** Extracts all the cookies as key-value pairs. */
export function getCookies(reqOrHeader: IncomingMessage | { headers?: Record<string, any> } | string): Record<string, string> {
    let header: string | undefined;

    if (typeof reqOrHeader === "string") {
        // Raw Header value
        header = reqOrHeader;
    } else {
        // Request from express
        const maybe = (reqOrHeader as any).headers?.cookie ?? (reqOrHeader as any).headers?.Cookie;
        header = typeof maybe === "string" ? maybe : undefined;
    }

    const result: Record<string, string> = {};
    if (!header) return result;

    // Split on ';' and parse name=value pairs. Keep first '=' as separator.
    for (const cookie of header.split(";")) {
        const idx = cookie.indexOf("=");
        if (idx < 0) { 
            const name = cookie.trim();
            if (name) result[name] = "";
            continue;
        }
        
        const name = cookie.slice(0, idx).trim();
        const val = cookie.slice(idx + 1).trim();
        try {
            result[name] = decodeURIComponent(val);
        } catch {
            result[name] = val;
        }
    }

    return result;
}