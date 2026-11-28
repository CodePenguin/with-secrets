import { createRoot } from 'react-dom/client'
import { App } from './App'
import { Providers } from './providers'
import './styles/tokens.css'
import './styles/global.css'

const root = document.getElementById('root')
if (!root) throw new Error('the page has no #root element')

createRoot(root).render(
  <Providers>
    <App />
  </Providers>,
)
