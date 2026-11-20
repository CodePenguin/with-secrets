using System.Net;

namespace WithSecrets.E2E;

/// <summary>The demo of one scenario as a page of screenshots to step through: Back and Next (or the arrow keys), the caption of each step under it, and the list of steps.</summary>
internal static class DemoViewer
{
    public static string Page(string scenario, string stepsJson) => Template.Replace("{{TITLE}}", WebUtility.HtmlEncode(scenario), StringComparison.Ordinal).Replace("{{STEPS}}", stepsJson, StringComparison.Ordinal);

    private const string Template = """
        <!doctype html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>{{TITLE}}</title>
          <style>
            :root{color-scheme:light dark;--bg:#fff;--fg:#20242b;--muted:#68717d;--line:#d9dde3;--panel:#f5f6f8;--accent:#1d4ed8}
            @media (prefers-color-scheme:dark){:root{--bg:#10151c;--fg:#e6edf5;--muted:#9fb3c8;--line:#2c3644;--panel:#171f2a;--accent:#7aa2ff}}
            *{box-sizing:border-box}
            body{margin:0;background:var(--bg);color:var(--fg);font:16px system-ui,sans-serif;height:100vh;display:grid;grid-template-columns:20rem minmax(0,1fr)}
            nav{border-right:1px solid var(--line);overflow:auto;background:var(--panel)}
            nav h1{font-size:1rem;margin:0;padding:14px 16px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--panel)}
            nav a{display:block;padding:9px 16px;color:inherit;text-decoration:none;border-bottom:1px solid var(--line);font-size:.9rem;line-height:1.35}
            nav a span{color:var(--muted);margin-right:6px}
            nav a[aria-current=step]{background:var(--accent);color:#fff}
            nav a[aria-current=step] span{color:#fff}
            main{display:grid;grid-template-rows:auto minmax(0,1fr) auto;min-width:0}
            .bar{display:flex;gap:12px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line)}
            .bar .count{margin-left:auto;color:var(--muted)}
            button{font:inherit;padding:6px 16px;border:1px solid var(--line);border-radius:6px;background:var(--panel);color:inherit;cursor:pointer}
            button:disabled{opacity:.4;cursor:default}
            .shot{overflow:auto;padding:16px;display:flex;justify-content:center;align-items:flex-start}
            .shot img{max-width:100%;max-height:100%;object-fit:contain;border:1px solid var(--line)}
            .caption{min-height:5.5rem;padding:14px 20px;border-top:1px solid var(--line);background:var(--panel);font-size:1.1rem;line-height:1.45}
            @media (max-width:800px){body{grid-template-columns:1fr;grid-template-rows:auto 1fr;height:auto}nav{max-height:30vh;border-right:0;border-bottom:1px solid var(--line)}}
          </style>
        </head>
        <body>
          <nav aria-label="Steps"><h1>{{TITLE}}</h1><div id="list"></div></nav>
          <main>
            <div class="bar">
              <button id="back" type="button">&larr; Back</button>
              <button id="next" type="button">Next &rarr;</button>
              <span class="count" id="count" aria-live="polite"></span>
            </div>
            <div class="shot"><img id="img" alt=""></div>
            <div class="caption" id="caption" aria-live="polite"></div>
          </main>
          <script>
            const steps = {{STEPS}};
            const $ = (id) => document.getElementById(id);
            let at = Math.max(0, Math.min(steps.length - 1, (parseInt(location.hash.slice(1), 10) || 1) - 1));
            const list = $('list');
            steps.forEach((step, index) => {
              const a = document.createElement('a');
              a.href = '#' + (index + 1);
              const n = document.createElement('span');
              n.textContent = index + 1;
              a.append(n, step.caption);
              a.addEventListener('click', (event) => { event.preventDefault(); go(index); });
              list.appendChild(a);
            });
            function go(index) {
              at = Math.max(0, Math.min(steps.length - 1, index));
              $('img').src = steps[at].image;
              $('img').alt = 'Step ' + (at + 1) + ': ' + steps[at].caption;
              $('caption').textContent = steps[at].caption;
              $('count').textContent = 'Step ' + (at + 1) + ' of ' + steps.length;
              $('back').disabled = at === 0;
              $('next').disabled = at === steps.length - 1;
              [...list.children].forEach((a, i) => { if (i === at) { a.setAttribute('aria-current', 'step'); a.scrollIntoView({ block: 'nearest' }); } else a.removeAttribute('aria-current'); });
              history.replaceState(null, '', '#' + (at + 1));
              if (steps[at + 1]) new Image().src = steps[at + 1].image;
            }
            $('back').addEventListener('click', () => go(at - 1));
            $('next').addEventListener('click', () => go(at + 1));
            document.addEventListener('keydown', (event) => {
              if (event.key === 'ArrowRight' || event.key === 'PageDown' || event.key === ' ') { event.preventDefault(); go(at + 1); }
              else if (event.key === 'ArrowLeft' || event.key === 'PageUp') { event.preventDefault(); go(at - 1); }
              else if (event.key === 'Home') go(0);
              else if (event.key === 'End') go(steps.length - 1);
            });
            go(at);
          </script>
        </body>
        </html>
        """;
}
