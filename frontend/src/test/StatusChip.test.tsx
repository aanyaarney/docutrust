import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';

import { StatusChip } from '../components/StatusChip';
import { CheckCard } from '../components/CheckCard';
import { presentIntegrity, presentRevocation, presentTimestamp } from '../components/verdict';

describe('status rendering', () => {
  it('shows a readable text label, not colour alone', () => {
    render(<StatusChip presentation={presentIntegrity('MODIFIED')} />);

    // The word must be present in the DOM: a user who cannot distinguish red
    // from green must still be able to read the outcome.
    expect(screen.getByText('Modified')).toBeInTheDocument();
  });

  it('gives assistive technology the full explanation', () => {
    render(<StatusChip presentation={presentRevocation('NOT_CHECKED')} />);

    const labelled = screen.getByLabelText(/Not checked/i);
    expect(labelled).toBeInTheDocument();
    expect(labelled.getAttribute('aria-label')).toMatch(/nothing was verified/i);
  });

  it('never labels an unchecked revocation as good', () => {
    render(<StatusChip presentation={presentRevocation('NOT_CHECKED')} />);

    expect(screen.queryByText('Good')).not.toBeInTheDocument();
    expect(screen.getByText('Not checked')).toBeInTheDocument();
  });

  it('never labels a missing timestamp as valid', () => {
    render(<CheckCard title="Trusted timestamp" presentation={presentTimestamp('NOT_AVAILABLE')} />);

    expect(screen.getByText('Trusted timestamp')).toBeInTheDocument();
    expect(screen.getByText('Not available')).toBeInTheDocument();
    expect(screen.queryByText('Valid')).not.toBeInTheDocument();
  });

  it('renders a check card with its title and status together', () => {
    render(<CheckCard title="Document integrity" presentation={presentIntegrity('INTACT')} />);

    expect(screen.getByText('Document integrity')).toBeInTheDocument();
    expect(screen.getByText('Intact')).toBeInTheDocument();
  });
});
