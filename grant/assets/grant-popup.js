(() => {
  "use strict";

  const root = document.documentElement;
  const allowed = String(root.dataset.grantAllowedOrigins || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const requested = String(root.dataset.grantParentOrigin || "");
  const parentOrigin = allowed.includes(requested) ? requested : "";
  const grantId = String(root.dataset.grantId || "");
  const decision = String(root.dataset.grantDecision || "");
  const complete = root.dataset.grantComplete === "true";
  const decisions = ["approve", "auto_rule", "always", "reject"];

  function post(type, detail) {
    if (!window.opener || !parentOrigin) return;
    window.opener.postMessage(
      { source: "grant-approval", type, grantId, ...detail },
      parentOrigin
    );
  }

  if (complete && decisions.includes(decision)) {
    post("grant:decision", { decision });
    window.setTimeout(() => window.close(), 250);
  } else if (window.opener) {
    post("grant:ready", {});
  }

  window.addEventListener("message", (event) => {
    if (!parentOrigin || event.origin !== parentOrigin) return;
    if (event.source !== window.opener) return;
    if (event.data && event.data.source === "grant-host" && event.data.type === "grant:close") {
      window.close();
    }
  });
})();
