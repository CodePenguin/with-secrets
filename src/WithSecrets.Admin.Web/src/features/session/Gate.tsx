import type { ReactNode } from 'react'
import { useSession } from '../../api/queries'
import { Button } from '../../components/Button'
import { Loading, ProblemAlert } from '../../components/Feedback'
import { SignInPage } from './SignInPage'

/** Shows the view only with a signed-in (read-only) session; otherwise the sign-in takes its place at the same address. */
export function Gate({ children }: { children: ReactNode }) {
  const session = useSession()
  if (session.isPending) return <Loading what="the session" />
  if (session.isError) {
    return (
      <>
        <ProblemAlert error={session.error} title="The session could not be read" />
        <p>
          <Button onClick={() => void session.refetch()}>Try again</Button>
        </p>
      </>
    )
  }
  if (!session.data.authenticated) return <SignInPage />

  return <>{children}</>
}
