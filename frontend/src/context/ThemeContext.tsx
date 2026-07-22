import { createContext, useContext, useState, type ReactNode } from "react"
import { theme as antdTheme, ConfigProvider } from "antd"

export type ThemeKey = "light" | "dark" | "tech-blue" | "eye-green"

export interface ThemeProfile {
  key: ThemeKey
  label: string
  // antd algorithm (defaultAlgorithm | darkAlgorithm)
  algorithm: typeof antdTheme.defaultAlgorithm
  // theme token overrides (colorPrimary, colorBgBase, ...)
  token: Record<string, string>
  // Sider / Menu theme to pair with this profile
  siderTheme: "light" | "dark"
}

// Four UI styles the operator can switch between. tech-blue is a dark,
// neon-blue palette suited for the security operations dashboard; eye-green
// is a low-contrast light palette for extended reading.
export const THEMES: Record<ThemeKey, ThemeProfile> = {
  light: {
    key: "light",
    label: "亮色",
    algorithm: antdTheme.defaultAlgorithm,
    token: { colorPrimary: "#1677ff" },
    siderTheme: "light",
  },
  dark: {
    key: "dark",
    label: "暗色",
    algorithm: antdTheme.darkAlgorithm,
    token: { colorPrimary: "#1668dc" },
    siderTheme: "dark",
  },
  "tech-blue": {
    key: "tech-blue",
    label: "科技蓝",
    algorithm: antdTheme.darkAlgorithm,
    token: { colorPrimary: "#00d4ff", colorBgBase: "#0a1929" },
    siderTheme: "dark",
  },
  "eye-green": {
    key: "eye-green",
    label: "护眼绿",
    algorithm: antdTheme.defaultAlgorithm,
    token: { colorPrimary: "#52c41a", colorBgBase: "#f0f7ed" },
    siderTheme: "light",
  },
}

interface ThemeContextValue {
  themeKey: ThemeKey
  setThemeKey: (k: ThemeKey) => void
  profile: ThemeProfile
}

const ThemeContext = createContext<ThemeContextValue>({
  themeKey: "light",
  setThemeKey: () => {},
  profile: THEMES.light,
})

const STORAGE_KEY = "theme"

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [themeKey, setThemeKeyState] = useState<ThemeKey>(() => {
    // P3-7 修复：localStorage 在隐私模式/禁用时会抛错，加 try/catch。
    try {
      const saved = (localStorage.getItem(STORAGE_KEY) as ThemeKey | null) ?? null
      return saved && THEMES[saved] ? saved : "light"
    } catch {
      return "light"
    }
  })

  const setThemeKey = (k: ThemeKey) => {
    // P3-7 修复：校验 key 合法 + setItem 容错（隐私模式 setItem 抛 QuotaExceededError）。
    if (!THEMES[k]) return
    setThemeKeyState(k)
    try {
      localStorage.setItem(STORAGE_KEY, k)
    } catch { /* localStorage 不可用，仅内存切换 */ }
  }

  const profile = THEMES[themeKey]

  return (
    <ThemeContext.Provider value={{ themeKey, setThemeKey, profile }}>
      <ConfigProvider theme={{ algorithm: profile.algorithm, token: profile.token }}>
        {children}
      </ConfigProvider>
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  return useContext(ThemeContext)
}
