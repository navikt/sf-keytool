let currentTestCn = null;
let existingCns = new Set();

async function loadCerts() {
    const res = await fetch("/internal/cert/list");
    const list = await res.json();

    const deprecatedCns = showDuplicateWarnings(list);


    const tbody = document.getElementById("certTable");
    tbody.innerHTML = "";

    const expiryWarnings = [];

    existingCns.clear()
    list.forEach(c => {
        existingCns.add(c.cn);

        if (c.daysLeft < 90) {
            const status =
                c.daysLeft < 1
                    ? "has expired"
                    : `expires in ${c.daysLeft} days`;

            expiryWarnings.push(
                `Certificate <strong>${c.cn}</strong> ${status}`
            );
        }

        const tr = document.createElement("tr");
        const warn = c.daysLeft < 60 ? "warn" : "";

        const isTmp = c.source === "tmp";

        const isVerified = (isTmp && c.sfClientId);
        const isNew = (isTmp && !c.sfClientId);

        const warnExpiry = c.daysLeft < 90;

        if (warnExpiry) {
            tr.classList.add("expires-soon");
        }

        if (deprecatedCns && deprecatedCns.has(c.cn)) {
            tr.classList.add("deprecated");
        }

        if (isVerified) {
            tr.classList.add("verified");
        }

        if (isNew) {
            tr.classList.add("new");
        }

        tr.innerHTML = `
  <td>${c.cn}</td>
  <td>${c.expiresAt}</td>
  <td class="${warnExpiry ? 'warn' : ''}">${c.daysLeft}</td>

      <td class="center">
        ${isTmp
            ? `<button title="Download certificate" onclick="download('${c.cn}', 'cer')" data-variant="tertiary" class="icon-btn aksel-button aksel-button--tertiary aksel-button--small aksel-button--icon-only"><!----><!----><span class="aksel-button__icon"><!----><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" focusable="false" role="img" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" fill-rule="evenodd" d="M12 2.75a.75.75 0 0 1 .75.75v9.19l2.72-2.72a.75.75 0 1 1 1.06 1.06l-4 4a.75.75 0 0 1-1.06 0l-4-4a.75.75 0 1 1 1.06-1.06l2.72 2.72V3.5a.75.75 0 0 1 .75-.75M5.75 18a.75.75 0 0 1 .75-.75h11a.75.75 0 0 1 0 1.5h-11a.75.75 0 0 1-.75-.75" clip-rule="evenodd"/></svg></span></button>`
            : ``}
      </td>
      <td class="center">
        ${isTmp
            ? `<button title="Verify against Salesforce config" onclick="openTestModal('${c.cn}')" data-variant="tertiary" class="icon-btn aksel-button aksel-button--tertiary aksel-button--small aksel-button--icon-only"><span class="aksel-button__icon"><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="none" focusable="false" role="img" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" fill-rule="evenodd" d="M11.286 11.483a.75.75 0 0 1 .099-.33l4.5-7.795a2.75 2.75 0 0 1 4.763 2.75l-4.5 7.795a.75.75 0 0 1-.236.25l-3.732 2.465a.75.75 0 0 1-1.162-.671zm1.486.266-.167 2.79L14.937 13l3.028-5.243-2.165-1.25zm6.577-6.39-.634 1.097-2.165-1.25.634-1.098a1.25 1.25 0 1 1 2.165 1.25M12.5 4.75H5.75v15.5h11.5V15.5a.75.75 0 0 1 1.5 0v5c0 .69-.56 1.25-1.25 1.25h-12c-.69 0-1.25-.56-1.25-1.25v-16c0-.69.56-1.25 1.25-1.25h7a.75.75 0 0 1 0 1.5" clip-rule="evenodd"></path></svg></span></button>`
            : ``}
      </td>
      <td class="center">
        ${isTmp
            ? `<button title="Copy JKS Base64" onclick="copy('${c.cn}', 'jksb64', 'KEYSTORE_JKS_B64')" type="button" data-active="false" data-variant="tertiary" class="icon-btn aksel-copybutton aksel-button aksel-button&#45;&#45;tertiary aksel-button&#45;&#45;small aksel-button&#45;&#45;icon-only"><span class="aksel-button__icon"><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="none" focusable="false" role="img" viewBox="0 0 24 24" aria-labelledby="c267" aria-hidden="false" class="aksel-copybutton__icon"><title id="c267">Copy</title><path fill="currentColor" fill-rule="evenodd" d="M8.25 3.5c0-.69.56-1.25 1.25-1.25H14a.75.75 0 0 1 .53.22l5 5c.141.14.22.331.22.53v8.5c0 .69-.56 1.25-1.25 1.25h-9c-.69 0-1.25-.56-1.25-1.25zm6.25 5.25c-.69 0-1.25-.56-1.25-1.25V3.75h-3.5v12.5h8.5v-7.5zm.25-3.94 2.44 2.44h-2.44zM6.502 7.75H5.75v12.5h8.5v-.748a.75.75 0 0 1 1.5 0v.998c0 .69-.56 1.25-1.25 1.25h-9c-.69 0-1.25-.56-1.25-1.25v-13c0-.69.56-1.25 1.25-1.25h1.002a.75.75 0 1 1 0 1.5" clip-rule="evenodd"></path></svg></span>  </button>`
            : ``}
      </td>

      <td class="center">
        ${isTmp
            ? `<button title="Copy JKS keystore password" onclick="copy('${c.cn}', 'password', 'KEYSTORE_PASSWORD')" type="button" data-active="false" data-variant="tertiary" class="icon-btn aksel-copybutton aksel-button aksel-button&#45;&#45;tertiary aksel-button&#45;&#45;small aksel-button&#45;&#45;icon-only"><span class="aksel-button__icon"><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="none" focusable="false" role="img" viewBox="0 0 24 24" aria-labelledby="c267" aria-hidden="false" class="aksel-copybutton__icon"><title id="c267">Copy</title><path fill="currentColor" fill-rule="evenodd" d="M8.25 3.5c0-.69.56-1.25 1.25-1.25H14a.75.75 0 0 1 .53.22l5 5c.141.14.22.331.22.53v8.5c0 .69-.56 1.25-1.25 1.25h-9c-.69 0-1.25-.56-1.25-1.25zm6.25 5.25c-.69 0-1.25-.56-1.25-1.25V3.75h-3.5v12.5h8.5v-7.5zm.25-3.94 2.44 2.44h-2.44zM6.502 7.75H5.75v12.5h8.5v-.748a.75.75 0 0 1 1.5 0v.998c0 .69-.56 1.25-1.25 1.25h-9c-.69 0-1.25-.56-1.25-1.25v-13c0-.69.56-1.25 1.25-1.25h1.002a.75.75 0 1 1 0 1.5" clip-rule="evenodd"></path></svg></span>  </button>`
            : ``}
      </td>

      <td class="center">
  ${
            isTmp && c.sfClientId
                ? `<button title="Copy SF Client ID" onclick="copyValue('${c.sfClientId}', 'SF_CLIENT_ID')" type="button" data-active="false" data-variant="tertiary" class="icon-btn aksel-copybutton aksel-button aksel-button&#45;&#45;tertiary aksel-button&#45;&#45;small aksel-button&#45;&#45;icon-only"><span class="aksel-button__icon"><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="none" focusable="false" role="img" viewBox="0 0 24 24" aria-labelledby="c267" aria-hidden="false" class="aksel-copybutton__icon"><title id="c267">Copy</title><path fill="currentColor" fill-rule="evenodd" d="M8.25 3.5c0-.69.56-1.25 1.25-1.25H14a.75.75 0 0 1 .53.22l5 5c.141.14.22.331.22.53v8.5c0 .69-.56 1.25-1.25 1.25h-9c-.69 0-1.25-.56-1.25-1.25zm6.25 5.25c-.69 0-1.25-.56-1.25-1.25V3.75h-3.5v12.5h8.5v-7.5zm.25-3.94 2.44 2.44h-2.44zM6.502 7.75H5.75v12.5h8.5v-.748a.75.75 0 0 1 1.5 0v.998c0 .69-.56 1.25-1.25 1.25h-9c-.69 0-1.25-.56-1.25-1.25v-13c0-.69.56-1.25 1.25-1.25h1.002a.75.75 0 1 1 0 1.5" clip-rule="evenodd"></path></svg></span>  </button>`
                : (!isTmp && c.sfClientId
                    ? `<span title="Masked Client ID">${c.sfClientId}</span>`
                    : ``)
        }
</td>

      <td class="center">
  ${
            isTmp && c.sfUsername
                ? `<button title="Copy SF Username" onclick="copyValue('${c.sfUsername}', 'SF_USERNAME')" type="button" data-active="false" data-variant="tertiary" class="icon-btn aksel-copybutton aksel-button aksel-button&#45;&#45;tertiary aksel-button&#45;&#45;small aksel-button&#45;&#45;icon-only"><span class="aksel-button__icon"><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="none" focusable="false" role="img" viewBox="0 0 24 24" aria-labelledby="c267" aria-hidden="false" class="aksel-copybutton__icon"><title id="c267">Copy</title><path fill="currentColor" fill-rule="evenodd" d="M8.25 3.5c0-.69.56-1.25 1.25-1.25H14a.75.75 0 0 1 .53.22l5 5c.141.14.22.331.22.53v8.5c0 .69-.56 1.25-1.25 1.25h-9c-.69 0-1.25-.56-1.25-1.25zm6.25 5.25c-.69 0-1.25-.56-1.25-1.25V3.75h-3.5v12.5h8.5v-7.5zm.25-3.94 2.44 2.44h-2.44zM6.502 7.75H5.75v12.5h8.5v-.748a.75.75 0 0 1 1.5 0v.998c0 .69-.56 1.25-1.25 1.25h-9c-.69 0-1.25-.56-1.25-1.25v-13c0-.69.56-1.25 1.25-1.25h1.002a.75.75 0 1 1 0 1.5" clip-rule="evenodd"></path></svg></span>  </button>`
                : (!isTmp && c.sfUsername
                    ? `<span title="Integration user">${c.sfUsername}</span>`
                    : ``)
        }
</td>
      <td class="center">
      <button title="Delete certificate information" onclick="deleteCert('${c.cn}', '${c.source}')" data-color="neutral" data-variant="tertiary" class="icon-btn aksel-button aksel-button--tertiary-neutral aksel-button--small aksel-button--icon-only"><!----><!----><span class="aksel-button__icon"><!----><svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" fill="none" focusable="false" role="img" viewBox="0 0 24 24" style="color: var(--ax-text-danger-decoration) !important;"><!----><!----><path fill="currentColor" fill-rule="evenodd" d="M4.5 6.25a.75.75 0 0 0 0 1.5h.805l.876 11.384a1.75 1.75 0 0 0 1.745 1.616h8.148a1.75 1.75 0 0 0 1.745-1.616l.876-11.384h.805a.75.75 0 0 0 0-1.5h-2.75V6A2.75 2.75 0 0 0 14 3.25h-4A2.75 2.75 0 0 0 7.25 6v.25zm5.5-1.5c-.69 0-1.25.56-1.25 1.25v.25h6.5V6c0-.69-.56-1.25-1.25-1.25zm-3.19 3 .867 11.27c.01.13.118.23.249.23h8.148c.13 0 .24-.1.25-.23l.866-11.27zm3.19 2a.75.75 0 0 1 .75.75v6a.75.75 0 0 1-1.5 0v-6a.75.75 0 0 1 .75-.75m4 0a.75.75 0 0 1 .75.75v6a.75.75 0 0 1-1.5 0v-6a.75.75 0 0 1 .75-.75" clip-rule="evenodd"></path></svg></span></button>
</td>
`;
        tbody.appendChild(tr);
    });
    const expiryBox = document.getElementById("expiryWarnings");

    if (expiryWarnings.length === 0) {
        expiryBox.innerHTML = "";
    } else {
        expiryBox.innerHTML = `
        <div class="warning-block">
            <strong>⏰ Certificates nearing expiration</strong>
            ${expiryWarnings.map(w => `<div class="warning-row">${w}</div>`).join("")}
        </div>
    `;
    }
}

function last10(str) {
    if (!str) return null;
    return str.slice(-10);
}

function showDuplicateWarnings(list) {
    const deprecated = new Set();

    // Group certs by last-10 of SF_CLIENT_ID
    const groups = new Map();

    list.forEach(c => {
        if (!c.sfClientId) return;

        const key = last10(c.sfClientId);
        if (!key) return;

        if (!groups.has(key)) {
            groups.set(key, []);
        }
        groups.get(key).push(c);
    });

    let warnings = [];

    groups.forEach(certs => {
        if (certs.length <= 1) return;

        // Sort by expiresAt DESC (newest first)
        certs.sort(
            (a, b) => new Date(b.expiresAt) - new Date(a.expiresAt)
        );

        // All except newest are deprecated
        certs.slice(1).forEach(c => {
            deprecated.add(c.cn);
            warnings.push(
                `Certificate <strong>${c.cn}</strong> has been replaced. Associated client id: ***${last10(c.sfClientId)}`
            );

        });
    });

    const warningsDiv = document.getElementById("certWarnings");

    if (warnings.length > 0) {
        warningsDiv.innerHTML = `
        <div class="warning-block">
            <strong>⚠ Duplicate Salesforce configuration</strong>
            ${warnings.map(w => `<div class="warning-row">${w}</div>`).join("")}
        </div>
    `;
    }

    return deprecated;
}

function copyValue(value, lbl) {
    navigator.clipboard.writeText(value);
    showToast("Copied " + lbl + " to clipboard");
}

function download(cn, type) {
    window.location = `/internal/cert/download/${cn}/${type}`;
}

async function copy(cn, type, lbl) {
    const res = await fetch(`/internal/cert/download/${cn}/${type}`);
    const text = await res.text();
    await navigator.clipboard.writeText(text);
    showToast("Copied " + lbl + " to clipboard");
}

/* ----- Modal ----- */

function openTestModal(cn) {
    currentTestCn = cn;
    document.getElementById("testCn").value = cn;
    document.getElementById("testResult").innerHTML = "";
    document.getElementById("testModal").style.display = "block";
}

function closeModal() {
    document.getElementById("testModal").style.display = "none";
}

function showToast(msg) {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.style.display = "block";

    setTimeout(() => {
        t.style.display = "none";
    }, 1500);
}

async function runTest() {
    const clientId = document.getElementById("testClientId").value;
    const username = document.getElementById("testUsername").value;

    const result = document.getElementById("testResult");
    result.textContent = "Testing...";
    result.className = "";

    const body = new URLSearchParams({
        cn: currentTestCn,
        clientId,
        username
    });

    const res = await fetch("/internal/cert/test", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body
    });

    const text = await res.text();
    result.textContent = text;
    result.className = res.ok ? "success" : "error";
    await loadCerts();
}

function deleteCert(cn, source) {
    openConfirmModal(
        "Delete certificate",
        `Delete certificate '${cn}'?\n\nThis cannot be undone.`,
        async () => {
            console.log("DELETE CERT delegated function");
            const body = new URLSearchParams({ cn, source });

            const res = await fetch("/internal/cert/delete", {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body
            });

            if (!res.ok) {
                showToast(await res.text());
                return;
            }

            await loadCerts();
        }
    );
}

function flushLocal() {
    openConfirmModal(
        "Flush local certificate cache",
        "This will remove ALL locally stored certificates and secrets.\n\n" +
        "Database metadata will remain.",
        async () => {
            const res = await fetch("/internal/cert/flush", {
                method: "POST"
            });

            if (!res.ok) {
                showToast(await res.text());
                return;
            }

            await loadCerts();
        }
    );
}

let confirmCallback = null;

function openConfirmModal(title, message, onConfirm) {
    document.getElementById("confirmTitle").innerText = title;
    document.getElementById("confirmMessage").innerText = message;

    confirmCallback = onConfirm;

    document.getElementById("confirmModal").style.display = "block";

    document.getElementById("confirmOkButton").onclick = () => {
        const cb = confirmCallback;
        closeConfirmModal();
        cb && cb();
    };
}

function closeConfirmModal() {
    document.getElementById("confirmModal").style.display = "none";
    confirmCallback = null;
}


/* ----- Generate ----- */

document.getElementById("generateForm").onsubmit = async e => {
    e.preventDefault();
    const f = e.target;
    const spinner = document.getElementById("generateSpinner");
    const cn = f.cn.value.trim();

    if (existingCns.has(cn)) {
        showToast(`Certificate with CN '${cn}' already exists`);
        return;
    }

    spinner.style.display = "block";
    f.querySelector("button").disabled = true;

    const body = new URLSearchParams({
        cn: cn,
        days: f.days.value
    });

    try {
        const res = await fetch("/internal/cert/generate", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body
        });

        if (!res.ok) {
            showToast(await res.text());
        } else {
            f.reset();
            await loadCerts();
        }
    } finally {
        spinner.style.display = "none";
        f.querySelector("button").disabled = false;
    }
};

async function loadContext() {
    try {
        const res = await fetch("/internal/context");
        if (!res.ok) return;

        const env = (await res.text()).trim().toUpperCase();
        document.getElementById("envTag").textContent = ` (${env})`;
    } catch (e) {
        console.warn("Could not load context", e);
    }
}

window.onload = function() {
    loadContext();
    checkAuthorization();
};

const checkAuthorization = async () => {
    const response = await fetch('/internal/secrethello', {
        method: 'GET'
    });

    if (response.status === 401) {
        // Unauthorized
        document.getElementById('authorization-message').innerHTML =
            'Unauthorized <button class="login-button" onclick="login()">Login</button>';
        return;
    }

    loadCerts();
};

const login = () => {
    window.location.href = '/oauth2/login?redirect=/internal/gui';
};