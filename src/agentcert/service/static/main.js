/* AgentCert Dashboard — Minimal JavaScript */

/* ── Copy to Clipboard ─────────────────────────────────────────────── */

function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(function () {
        btn.classList.add("copied");
        var orig = btn.textContent;
        btn.textContent = "\u2713";
        setTimeout(function () {
            btn.classList.remove("copied");
            btn.textContent = orig;
        }, 1500);
    });
}

document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".copy-btn").forEach(function (btn) {
        btn.addEventListener("click", function () {
            var text = btn.getAttribute("data-copy");
            if (text) copyToClipboard(text, btn);
        });
    });

    /* ── Auto-Refresh ──────────────────────────────────────────────── */

    if (document.querySelector(".auto-refresh")) {
        setInterval(function () {
            location.reload();
        }, 30000);
    }

    /* ── Explainer Toggle ──────────────────────────────────────────── */

    var explainerToggle = document.getElementById("explainer-toggle");
    var explainerPanel = document.getElementById("explainer-panel");
    var explainerDismiss = document.getElementById("explainer-dismiss");

    function closeExplainer() {
        if (explainerPanel) {
            explainerPanel.hidden = true;
            explainerToggle.setAttribute("aria-expanded", "false");
        }
    }

    if (explainerToggle && explainerPanel) {
        explainerToggle.addEventListener("click", function () {
            var open = explainerPanel.hidden;
            explainerPanel.hidden = !open;
            explainerToggle.setAttribute("aria-expanded", open ? "true" : "false");
        });
    }

    if (explainerDismiss) {
        explainerDismiss.addEventListener("click", closeExplainer);
    }

    /* ── Collapsible Sections ──────────────────────────────────────── */

    document.querySelectorAll(".collapsible-toggle").forEach(function (el) {
        el.addEventListener("click", function () {
            el.classList.toggle("collapsed");
            var target = document.getElementById(el.getAttribute("data-target"));
            if (target) target.classList.toggle("collapsed");
        });
    });

    /* ── Verify Form ───────────────────────────────────────────────── */

    var form = document.getElementById("verify-form");
    if (form) {
        form.addEventListener("submit", function (e) {
            e.preventDefault();
            var input = document.getElementById("entry-id-input");
            var entryId = input.value.trim();
            if (!entryId) return;

            var resultDiv = document.getElementById("verify-result");
            resultDiv.innerHTML = '<p style="color: var(--color-text-muted)">Verifying...</p>';

            fetch("/api/v1/verify/" + encodeURIComponent(entryId))
                .then(function (resp) {
                    if (resp.status === 404) {
                        throw new Error("Entry not found");
                    }
                    return resp.json();
                })
                .then(function (data) {
                    renderVerificationResult(data, resultDiv);
                })
                .catch(function (err) {
                    resultDiv.innerHTML = '<div class="verify-error">' + escapeHtml(err.message) + "</div>";
                });
        });
    }
});

/* ── Render Verification Result ────────────────────────────────────── */

function renderVerificationResult(data, container) {
    var checkNames = {
        entry_integrity: "Entry Integrity",
        agent_signature: "Agent Signature",
        cert_binding: "Certificate Binding",
        merkle_proof: "Merkle Proof",
        anchor_on_chain: "Bitcoin Anchor",
    };
    var checkDetails = {
        entry_integrity: "SHA-256(body) matches entry_id",
        agent_signature: "ECDSA signature valid",
        cert_binding: "cert_id matches registered certificate",
        merkle_proof: "Included in Merkle batch",
        anchor_on_chain: "Anchored to Bitcoin blockchain",
    };

    var html = '<div class="verification-panel">';
    var checks = data.checks || {};
    for (var key in checks) {
        var passed = checks[key];
        var icon = passed ? '<span class="check-pass">\u2713</span>' : '<span class="check-fail">\u2717</span>';
        html += '<div class="verification-check">';
        html += '<span class="check-icon">' + icon + "</span>";
        html += '<span class="check-name">' + (checkNames[key] || key) + "</span>";
        html += '<span class="check-detail">' + (checkDetails[key] || "") + "</span>";
        html += "</div>";
    }

    var statusClass = "status-" + data.status.toLowerCase().replace("_", "-");
    html += '<div class="verification-status ' + statusClass + '">';
    html += "Status: " + data.status;
    html += "</div></div>";

    if (data.certificate) {
        html += '<div style="margin-top: 12px; font-size: 13px; color: var(--color-text-secondary)">';
        html += "Agent: " + escapeHtml(data.certificate.agent_name || "Unknown");
        html += " &middot; ";
        html += '<a href="/dashboard/entries/' + encodeURIComponent(data.entry_id) + '">View entry details \u2192</a>';
        html += "</div>";
    }

    container.innerHTML = html;
}

/* ── Escape HTML ───────────────────────────────────────────────────── */

function escapeHtml(str) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}
