(() => {
  "use strict";

  // Layer 3 delivery surface: an injected script for browser/computer-use
  // agents. It pauses fetch/XHR calls and high-risk clicks until a human
  // decides in the hosted 460x640 Grant popup. No host page credentials are
  // read or forwarded.
  const script = document.currentScript;
  if (!script) return;

  const base = String(script.dataset.grantUrl || "").replace(/\/$/, "");
  if (!/^https?:\/\//.test(base)) return;

  const agent = String(script.dataset.agent || "web-agent").slice(0, 120);
  const workspace = String(script.dataset.workspace || "public").slice(0, 60);
  const sensitiveHosts = String(script.dataset.sensitivePaths || "stripe.com,googleapis.com")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  const riskyWords = String(script.dataset.riskyClicks || "send,pay,delete,transfer,publish")
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  const maxWaitMs = Math.max(1000, Number(script.dataset.maxWaitMs || 300000));

  const nativeFetch = window.fetch ? window.fetch.bind(window) : null;

  function hostOf(value) {
    try {
      return new URL(String(value), window.location.href).host.toLowerCase();
    } catch (_) {
      return "";
    }
  }

  function isGrantCall(value) {
    return String(value || "").startsWith(base);
  }

  function needsApproval(value) {
    if (!value || isGrantCall(value)) return false;
    const host = hostOf(value);
    return sensitiveHosts.some((pattern) => host === pattern || host.endsWith("." + pattern) || host.includes(pattern));
  }

  function openPopup(approvalUrl, grantId) {
    const width = 460;
    const height = 640;
    const left = Math.max(0, window.screenX + (window.outerWidth - width) / 2);
    const top = Math.max(0, window.screenY + (window.outerHeight - height) / 2);
    const features = `width=${width},height=${height},left=${Math.round(left)},top=${Math.round(top)}`;
    const popup = window.open(approvalUrl, "grant-approval", features);
    if (!popup) {
      window.dispatchEvent(new CustomEvent("grant:inject-blocked", { detail: { grantId } }));
    }
    return popup;
  }

  const pendingResolvers = Object.create(null);

  function requestApproval(action, summary, scope) {
    if (!nativeFetch) return Promise.resolve(false);
    return nativeFetch(base + "/v1/requests", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "omit",
      body: JSON.stringify({
        agent,
        action,
        summary,
        scope,
        workspace,
        channel: "browser_inject",
        parent_origin: window.location.origin,
      }),
    })
      .then((response) => (response.ok ? response.json() : null))
      .then((data) => {
        if (!data || !data.id || !data.approval_url) return false;
        const grantId = String(data.id);
        const popup = openPopup(String(data.approval_url), grantId);
        const started = Date.now();
        let settled = false;

        function finish(decision) {
          if (settled) return;
          settled = true;
          clearInterval(timer);
          window.removeEventListener("message", onMessage);
          if (popup && !popup.closed) popup.close();
          const resolve = pendingResolvers[grantId];
          delete pendingResolvers[grantId];
          window.dispatchEvent(
            new CustomEvent("grant:inject-decision", { detail: { grantId, decision } })
          );
          if (resolve) {
            resolve(decision === "approve" || decision === "always" || decision === "auto_rule");
          }
        }

        function onMessage(event) {
          const payload = event.data;
          if (!payload || payload.source !== "grant-approval") return;
          if (payload.grantId && payload.grantId !== grantId) return;
          if (payload.type === "grant:decision") finish(String(payload.decision || ""));
        }

        window.addEventListener("message", onMessage);
        const timer = setInterval(() => {
          nativeFetch(base + "/v1/requests/" + encodeURIComponent(grantId), {
            credentials: "omit",
            cache: "no-store",
          })
            .then((response) => (response.ok ? response.json() : null))
            .then((status) => {
              if (status && status.status === "decided") finish(String(status.decision || ""));
            })
            .catch(() => {});
          if (Date.now() - started > maxWaitMs) finish("timeout");
        }, 700);

        return new Promise((resolve) => {
          // finish() resolves through this wrapper so both the message and the
          // polling path share one completion channel.
          pendingResolvers[grantId] = resolve;
        });
      })
      .catch(() => false);
  }

  if (nativeFetch) {
    window.fetch = function (input, init) {
      const url = typeof input === "string" ? input : input && input.url ? input.url : "";
      if (!needsApproval(url)) return nativeFetch(input, init);
      const summary = `Allow this page to call ${hostOf(url)}?`;
      return requestApproval("outbound request", summary, {
        host: hostOf(url),
        method: (init && init.method) || "GET",
      }).then((allowed) => {
        if (!allowed) throw new Error("Grant approval is required for this request.");
        return nativeFetch(input, init);
      });
    };
  }

  if (window.XMLHttpRequest) {
    const nativeOpen = XMLHttpRequest.prototype.open;
    const nativeSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      this.__grantMeta = { method, url: String(url || "") };
      return nativeOpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function (body) {
      const meta = this.__grantMeta || {};
      if (!needsApproval(meta.url)) return nativeSend.call(this, body);
      const request = this;
      const summary = `Allow this page to call ${hostOf(meta.url)}?`;
      requestApproval("outbound request", summary, {
        host: hostOf(meta.url),
        method: meta.method || "GET",
      }).then((allowed) => {
        if (allowed) nativeSend.call(request, body);
        else request.abort();
      });
    };
  }

  document.addEventListener(
    "click",
    (event) => {
      const element = event.target && event.target.closest
        ? event.target.closest("button,input[type=submit],a[role=button]")
        : null;
      if (!element) return;
      const label = String(element.textContent || element.value || "").trim().toLowerCase();
      if (!label || !riskyWords.some((word) => label.includes(word))) return;
      if (element.__grantApproved) {
        delete element.__grantApproved;
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      requestApproval("high-risk click", `Allow this action: ${label.slice(0, 80)}`, {
        control: label.slice(0, 80),
      }).then((allowed) => {
        if (allowed) {
          element.__grantApproved = true;
          element.click();
        }
      });
    },
    true
  );
})();
