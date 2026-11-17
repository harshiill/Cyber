import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import BlockedIPs from '../BlockedIPs'
import http from '../../api/http'

vi.mock('../../api/http', () => ({ default: { get: vi.fn(), post: vi.fn() } }))

describe('BlockedIPs', () => {
  it('shows the API block list and retains a block when unblocking fails', async () => {
    http.get.mockImplementation((path) => Promise.resolve({ data: path === '/blocked'
      ? { blocked: [{ ip: '192.0.2.1', reason: 'Test', blocked_at: Date.now() / 1000, ttl: 300 }] }
      : { mode: 'enforce' } }))
    http.post.mockResolvedValue({ data: { action: 'failed', reason: 'Firewall unavailable' } })
    render(<BlockedIPs />)
    expect(await screen.findByText('192.0.2.1')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Unblock' }))
    expect(await screen.findByText(/Firewall unavailable/)).toBeInTheDocument()
    expect(screen.getByText('192.0.2.1')).toBeInTheDocument()
  })
})
