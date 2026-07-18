import { createContext, useContext, useState, useEffect, ReactNode } from "react"
import api, { login as loginApi } from "../api/client"

interface User { username: string; role: string; disabled: boolean }
interface AuthContextType {
  user: User | null; token: string | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void; loading: boolean
}

const AuthContext = createContext<AuthContextType>(null!)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(localStorage.getItem("token"))
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (token) {
      api.get("/auth/me")
        .then((res) => setUser(res.data))
        .catch(() => { localStorage.removeItem("token"); setToken(null) })
        .finally(() => setLoading(false))
    } else setLoading(false)
  }, [token])

  const loginFn = async (username: string, password: string) => {
    const data = await loginApi(username, password)
    localStorage.setItem("token", data.access_token)
    localStorage.setItem("role", data.role)
    setToken(data.access_token)
    const me = await api.get("/auth/me")
    setUser(me.data)
  }

  const logout = () => {
    localStorage.removeItem("token"); localStorage.removeItem("role")
    setToken(null); setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, token, login: loginFn, logout, loading }}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)