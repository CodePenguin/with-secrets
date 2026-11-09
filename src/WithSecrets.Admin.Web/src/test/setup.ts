import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'
import { setAntiForgery } from '../api/client'

// jsdom has no showModal/close on <dialog>: a faithful enough stand-in (open attribute, close event).
if (!HTMLDialogElement.prototype.showModal) {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.setAttribute('open', '')
  }
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.removeAttribute('open')
  }
}

afterEach(() => {
  cleanup()
  setAntiForgery(null)
})
