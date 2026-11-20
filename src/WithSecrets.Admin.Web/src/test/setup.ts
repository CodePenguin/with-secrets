import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, beforeEach } from 'vitest'
import { setBrowserSecret, setPendingAuthorization, setSessionSecret } from '../api/client'

// jsdom has no showModal/close on <dialog>: a faithful enough stand-in (open attribute, close event).
if (!HTMLDialogElement.prototype.showModal) {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.setAttribute('open', '')
  }
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.removeAttribute('open')
  }
}

// Every test starts as a page that has already made its browser identity (the tests of that step clear it).
beforeEach(() => {
  setBrowserSecret('test-browser-secret')
})

afterEach(() => {
  cleanup()
  setSessionSecret(null)
  setBrowserSecret(null)
  setPendingAuthorization(null)
})
