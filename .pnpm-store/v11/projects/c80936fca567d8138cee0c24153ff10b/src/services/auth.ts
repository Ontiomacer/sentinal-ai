const CLERK_WAIT_MS = 1500
const CLERK_POLL_MS = 50

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

const readClerkToken = async (): Promise<string | null> => {
  const clerk = (window as any).Clerk
  const token = await clerk?.session?.getToken?.()
  return token || null
}

export const getAuthToken = async (): Promise<string> => {
  const deadline = Date.now() + CLERK_WAIT_MS

  while (Date.now() < deadline) {
    const token = await readClerkToken()
    if (token) return token

    const clerk = (window as any).Clerk
    if (clerk?.loaded && !clerk?.session) break

    await delay(CLERK_POLL_MS)
  }

  const token = await readClerkToken()
  return token || localStorage.getItem('clerk_token') || import.meta.env.VITE_DEV_AUTH_TOKEN || 'user_dev'
}
