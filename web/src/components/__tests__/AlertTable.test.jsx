import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import AlertTable from '../AlertTable'

const ALERTS = [
  { id: '1', kind: 'flow', is_attack: true,  prediction: 'Attack', attack_prob: 0.97, src_ip: '1.1.1.1', src_port: 100, dst_ip: '2.2.2.2', dst_port: 80,  timestamp: '14:00:01' },
  { id: '2', kind: 'flow', is_attack: false, prediction: 'Benign', attack_prob: 0.03, src_ip: '3.3.3.3', src_port: 200, dst_ip: '4.4.4.4', dst_port: 443, timestamp: '14:00:02' },
  { id: '3', kind: 'flow', is_attack: true,  prediction: 'Attack', attack_prob: 0.91, src_ip: '5.5.5.5', src_port: 300, dst_ip: '6.6.6.6', dst_port: 80,  timestamp: '14:00:03' },
]

describe('AlertTable', () => {
  it('shows all rows by default', () => {
    render(<AlertTable alerts={ALERTS} selectedId={null} onSelect={vi.fn()} />)
    expect(screen.getAllByRole('row').length).toBe(ALERTS.length + 1)
  })

  it('filters to threats only', () => {
    render(<AlertTable alerts={ALERTS} selectedId={null} onSelect={vi.fn()} />)
    fireEvent.click(screen.getByText('Threats'))
    expect(screen.getAllByText('ATTACK').length).toBe(2)
    expect(screen.queryByText('BENIGN')).toBeNull()
  })

  it('filters to benign only', () => {
    render(<AlertTable alerts={ALERTS} selectedId={null} onSelect={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Benign' }))
    expect(screen.getAllByText('BENIGN').length).toBe(1)
    expect(screen.queryByText('ATTACK')).toBeNull()
  })

  it('calls onSelect when a row is clicked', () => {
    const onSelect = vi.fn()
    render(<AlertTable alerts={ALERTS} selectedId={null} onSelect={onSelect} />)
    fireEvent.click(screen.getAllByRole('row')[1])
    expect(onSelect).toHaveBeenCalledWith(ALERTS[0].id)
  })
})
