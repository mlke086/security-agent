import { useMemo } from "react"
import { marked } from "marked"
import DOMPurify from "dompurify"

/**
 * Markdown - lightweight MD renderer for assistant chat replies and
 * scan report summaries.
 *
 * Pipeline:
 *   1. Strip <think>...</think> reasoning traces (some models leak them).
 *   2. Parse markdown via `marked` (gfm + smart list, no auto <br>).
 *   3. Sanitize via DOMPurify to defuse XSS (LLM-controlled text).
 *   4. Render through dangerouslySetInnerHTML inside .md-content
 *      (caller's stylesheet provides typography).
 *
 * Why not react-markdown: marked + DOMPurify is ~50KB gzipped vs
 * react-markdown + remark-gfm + rehype-sanitize ~90KB. The savings
 * matter on a chat-heavy page.
 */

const THINK_RE = /<think>[\s\S]*?<\/think>/gi

marked.setOptions({
  gfm: true,
  breaks: false,
  pedantic: false,
})

function preprocess(source: string): string {
  // Drop <think>...</think> blocks. The LLM may emit them inline or
  // across line boundaries; the regex handles both.
  return source.replace(THINK_RE, "").trimStart()
}

interface Props {
  source: string
  className?: string
}

export default function Markdown({ source, className }: Props) {
  const html = useMemo(() => {
    if (!source) return ""
    const stripped = preprocess(source)
    if (!stripped) return ""
    const raw = marked.parse(stripped, { async: false }) as string
    return DOMPurify.sanitize(raw, {
      USE_PROFILES: { html: true },
      ADD_ATTR: ["target", "rel"],
    })
  }, [source])

  if (!html) return null
  return (
    <div
      className={`md-content${className ? ` ${className}` : ""}`}
      // HTML is already DOMPurify-sanitized (no scripts, no on* attrs).
      dangerouslySetInnerHTML={{ __html: html }}
    />
  )
}
