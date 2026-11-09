import { render } from '@testing-library/react'
import { App } from '../App'
import { Providers } from '../providers'

/** The whole application at a route (memory router), polling quickly. */
export function renderApp(route = '/') {
  return render(
    <Providers route={route} pollMs={10}>
      <App />
    </Providers>,
  )
}
