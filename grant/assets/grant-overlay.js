(() => {
  "use strict";

  const script = document.currentScript;
  if (!script) return;

  const approvalUrl = script.dataset.approvalUrl || "";
  if (!approvalUrl) return;

  let approval = null;
  try {
    approval = new URL(approvalUrl, window.location.href);
  } catch (_) {
    return;
  }
  const approvalOrigin = approval.origin;
  const expectedGrantId = approval.pathname.split("/").filter(Boolean).pop() || "";

  const label = script.dataset.label || "Review approval";
  const position = script.dataset.position === "bottom-left" ? "bottom-left" : "bottom-right";

  const host = document.createElement("div");
  host.setAttribute("data-grant-overlay", "");
  const shadow = host.attachShadow({ mode: "open" });

  const style = document.createElement("style");
  style.textContent = `
    :host { all: initial; font-family: Georgia, 'Times New Roman', serif; }
    .grant-launcher {
      position: fixed;
      ${position}: 20px;
      bottom: 20px;
      z-index: 2147483647;
      border: 1px solid #d8c7b2;
      border-radius: 999px;
      background: #fbf7ee;
      color: #6b1f2c;
      box-shadow: 0 12px 30px rgba(45, 23, 18, 0.18);
      padding: 12px 18px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      letter-spacing: 0.01em;
    }
    .grant-launcher:hover { background: #fffdf8; }
    .grant-launcher:focus-visible { outline: 3px solid rgba(107, 31, 44, 0.35); outline-offset: 3px; }
  `;

  const button = document.createElement("button");
  button.className = "grant-launcher";
  button.type = "button";
  button.textContent = label;
  button.setAttribute("aria-label", label);

  let popup = null;
  function openApproval() {
    const width = 460;
    const height = 640;
    const left = Math.max(0, window.screenX + (window.outerWidth - width) / 2);
    const top = Math.max(0, window.screenY + (window.outerHeight - height) / 2);
    // No `noopener`/`noreferrer`: the popup uses postMessage to resolve the
    // decision back to this page. The message handler below checks source.
    const features = `width=${width},height=${height},left=${Math.round(left)},top=${Math.round(top)}`;
    popup = window.open(approvalUrl, "grant-approval", features);
    if (!popup) {
      // Pop-up blocked: leave the host page intact and tell the caller.
      host.dispatchEvent(new CustomEvent("grant:blocked", { detail: { approvalUrl } }));
    }
  }

  button.addEventListener("click", openApproval);
  shadow.append(style, button);
  document.documentElement.appendChild(host);

  window.addEventListener("message", (event) => {
    if (event.origin !== approvalOrigin) return;
    if (!popup || event.source !== popup) return;
    const data = event.data;
    if (!data || data.source !== "grant-approval") return;
    if (expectedGrantId && data.grantId && data.grantId !== expectedGrantId) return;
    if (data.type === "grant:ready") {
      host.dispatchEvent(
        new CustomEvent("grant:ready", { detail: { grantId: data.grantId || expectedGrantId } })
      );
      return;
    }
    if (data.type === "grant:decision") {
      host.dispatchEvent(
        new CustomEvent("grant:decision", {
          detail: { grantId: data.grantId || expectedGrantId, decision: data.decision || "" },
        })
      );
      popup.close();
      popup = null;
    }
  });

  host.closeGrantPopup = () => {
    if (popup && !popup.closed) {
      popup.postMessage({ source: "grant-host", type: "grant:close" }, approvalOrigin);
    }
  };
})();
