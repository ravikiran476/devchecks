// PCI DSS v4.0.1 requirements this tool collects evidence for. Titles are paraphrased.

export interface Control {
  id: string;
  title: string;
  /** What the tool can show, and what a human still has to verify. */
  automated: string;
  manual: string;
}

export const CONTROLS: Record<string, Control> = {
  '6.4.3': {
    id: '6.4.3',
    title: 'Payment page scripts are authorized, integrity-assured and inventoried with a business justification',
    automated: 'Script inventory with hashes, comparison with the approved baseline, SRI coverage, justification present for each approved script.',
    manual: 'Confirm the approval workflow (who authorizes scripts), and that justifications are reviewed.',
  },
  '11.6.1': {
    id: '11.6.1',
    title: 'Change- and tamper-detection alerts on unauthorized changes to payment page scripts and security-impacting HTTP headers',
    automated: 'Captured CSP and security headers, script hashes; detects changes relative to the baseline when run on a schedule.',
    manual: 'Show that this check (or an equivalent) runs at least weekly or per your targeted risk analysis, and that alerts reach personnel who respond.',
  },
  '4.2.1': {
    id: '4.2.1',
    title: 'Strong cryptography protects PAN during transmission over open, public networks',
    automated: 'HTTPS for the page and card form targets; HSTS header.',
    manual: 'Verify TLS configuration and certificates (use a TLS scanner) for every endpoint that receives PAN.',
  },
  '3.3.1': {
    id: '3.3.1',
    title: 'Sensitive authentication data (e.g. CVV) is not retained after authorization',
    automated: 'Client-side code paths that log or store card security codes.',
    manual: 'Review server-side logging, analytics and storage of payment requests.',
  },
  '3.5.1': {
    id: '3.5.1',
    title: 'PAN is rendered unreadable wherever it is stored',
    automated: 'Client-side code paths that write card numbers to browser storage, cookies, logs or analytics.',
    manual: 'Review all server-side storage of PAN.',
  },
  '6.2.4': {
    id: '6.2.4',
    title: 'Software engineering techniques prevent or mitigate common attacks (e.g. injection, XSS)',
    automated: 'CSP strength as an XSS mitigation on the payment page.',
    manual: 'Secure code review and testing of the payment flow.',
  },
};

export const DISCLAIMER =
  'PCI PageCheck is a readiness aid. It collects technical evidence for selected PCI DSS requirements; it is not a PCI DSS assessment, does not establish compliance, and does not replace a QSA or your acquirer’s requirements.';
