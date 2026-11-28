namespace ArcanaGuardian.E2E;

/// <summary>Demo-only browser overlay that displays stdout and stderr as one terminal transcript.</summary>
internal static class DemoTerminal
{
    public const string Script = """
        () => {
            const mount = () => {
                if (!document.body || document.getElementById('__ws_demo_terminal')) return;
                const browser = document.createElement('div');
                browser.id = '__ws_demo_browser';
                for (const [name, value] of Object.entries({
                    position: 'fixed', left: '38vw', top: '0', width: '62vw', height: '100vh',
                    overflow: 'auto', background: 'transparent', 'box-sizing': 'border-box',
                    'overscroll-behavior': 'contain', 'z-index': '0'
                })) browser.style.setProperty(name, value, 'important');
                while (document.body.firstChild) browser.appendChild(document.body.firstChild);
                document.body.appendChild(browser);
                const moveToBrowser = new MutationObserver(records => {
                    for (const record of records) for (const node of record.addedNodes) {
                        if (node !== browser && node.id !== '__ws_demo_terminal' && node.parentNode === document.body) browser.appendChild(node);
                    }
                });
                moveToBrowser.observe(document.body, { childList: true });
                document.documentElement.style.setProperty('overflow', 'hidden', 'important');
                document.body.style.setProperty('overflow', 'hidden', 'important');
                document.body.style.setProperty('margin', '0', 'important');
                document.body.style.setProperty('width', '100vw', 'important');
                document.body.style.setProperty('height', '100vh', 'important');
                const layoutSheet = new CSSStyleSheet();
                layoutSheet.replaceSync(`
                    dialog[open] { position:fixed !important; left:calc(38vw + 24px) !important; right:24px !important;
                        top:24px !important; bottom:24px !important; width:min(40rem, calc(62vw - 48px)) !important;
                        max-width:calc(62vw - 48px) !important; max-height:calc(100vh - 48px) !important;
                        height:fit-content !important; margin:auto !important; }
                    dialog[open]::backdrop { background:linear-gradient(90deg, transparent 0 38vw, rgba(0,0,0,.45) 38vw 100%) !important; }
                `);
                document.adoptedStyleSheets = [...document.adoptedStyleSheets, layoutSheet];
                const panel = document.createElement('section');
                panel.id = '__ws_demo_terminal';
                panel.setAttribute('aria-hidden', 'true');
                panel.setAttribute('popover', 'manual');
                const styles = {
                    position: 'fixed', left: '0', top: '0', bottom: '0', width: '38vw', height: '100vh', 'max-height': '100vh', inset: '0 auto 0 0',
                    display: 'grid', 'grid-template-rows': 'auto auto minmax(0,1fr)', gap: '0', padding: '0', margin: '0',
                    background: '#0b111a', color: '#e6edf5',
                    'font-family': 'Consolas, ui-monospace, monospace', 'font-size': '13px',
                    'line-height': '1.4', 'z-index': '2147483000', 'box-sizing': 'border-box',
                    border: '1px solid #394454', 'box-shadow': '8px 0 28px rgba(0,0,0,.3)',
                    'pointer-events': 'none'
                };
                for (const [name, value] of Object.entries(styles)) panel.style.setProperty(name, value, 'important');

                const heading = document.createElement('div');
                heading.textContent = 'CLI · terminal';
                for (const [name, value] of Object.entries({
                    color: '#9fb3c8', 'font-family': 'system-ui,sans-serif', 'font-size': '11px',
                    'font-weight': '700', 'letter-spacing': '.09em', 'text-transform': 'uppercase',
                    padding: '10px 12px', 'border-bottom': '1px solid #394454',
                    background: '#111a26', 'box-sizing': 'border-box'
                })) heading.style.setProperty(name, value, 'important');

                const output = document.createElement('pre');
                for (const [name, value] of Object.entries({
                    margin: '0', padding: '12px', color: '#e6edf5', background: '#0b111a',
                    'white-space': 'pre-wrap', 'overflow-wrap': 'anywhere', 'overflow-y': 'auto',
                    'min-height': '0', 'font-family': 'inherit', 'font-size': 'inherit',
                    'line-height': 'inherit', 'box-sizing': 'border-box'
                })) output.style.setProperty(name, value, 'important');

                const caption = document.createElement('div');
                caption.id = '__ws_demo_caption';
                caption.setAttribute('aria-hidden', 'true');
                caption.style.cssText = 'display:block; box-sizing:border-box; padding:18px 20px; height:120px; border-bottom:1px solid #526174; background:#172333; color:#fff; font:650 18px/1.4 system-ui,sans-serif; overflow-wrap:anywhere;';
                const empty = document.createElement('div');
                empty.textContent = 'No terminal output in this step.';
                empty.style.cssText = 'color:#9fb3c8; padding:12px; font:13px/1.4 Consolas,ui-monospace,monospace;';
                output.appendChild(empty);
                panel.append(caption, heading, output);
                document.body.appendChild(panel);
                try { panel.showPopover(); } catch (_) {}

                let lastTranscript = '';
                const refresh = async () => {
                    if (!/^https?:$/.test(location.protocol)) return;
                    try {
                        const response = await fetch('/__ws_demo_terminal', { cache: 'no-store' });
                        if (!response.ok) return;
                        const data = await response.json();
                        const transcript = data.transcript || '';
                        if (transcript !== lastTranscript) {
                            output.textContent = transcript || 'No terminal output in this step.';
                            output.scrollTop = output.scrollHeight;
                            lastTranscript = transcript;
                        }
                    } catch (_) { /* Navigation or a closed one-shot server. */ }
                };
                window.__wsDemoTerminalRefresh = refresh;
                refresh();
                window.addEventListener('pagehide', () => {
                    moveToBrowser.disconnect();
                }, { once: true });
            };
            if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, { once: true });
            else mount();
        }
        """;
}
