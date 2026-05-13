/**
 * Admin Login SSO — admin settings page JS.
 *
 * - Saves the Google Client Secret over AJAX with a JSON body and a
 *   base64-encoded value under a neutral field name (WAF-safe path).
 * - Copy-to-clipboard delegation for any element marked data-action="copy".
 * - Live "parsed domains" chip preview for the Allowed Domains textarea.
 * - Synchronous format validation for the Client ID input.
 * - Focus management + aria-busy for screen-reader users.
 */
(function () {
	'use strict';

	if (typeof window.AdminLoginSsoSecret === 'undefined') {
		return;
	}

	var cfg = window.AdminLoginSsoSecret;

	function byId(id) {
		return document.getElementById(id);
	}

	/* -----------------------------------------------------------------
	 * Secret AJAX save flow
	 * ----------------------------------------------------------------- */

	var section   = byId('admin-login-sso-secret-section');
	var statusEl  = byId('admin-login-sso-secret-status');
	var savedView = section ? section.querySelector('.admin-login-sso-secret-saved') : null;
	var formView  = section ? section.querySelector('.admin-login-sso-secret-form') : null;
	var maskEl    = byId('admin-login-sso-secret-mask');
	var input     = byId('admin-login-sso-secret-input');
	var saveBtn   = byId('admin-login-sso-secret-save-btn');
	var clearBtn  = byId('admin-login-sso-secret-clear-btn');
	var updateBtn = byId('admin-login-sso-secret-update-btn');
	var cancelBtn = byId('admin-login-sso-secret-cancel-btn');
	var feedback  = byId('admin-login-sso-secret-feedback');

	function setHidden(el, hidden) {
		if (!el) { return; }
		if (hidden) {
			el.setAttribute('hidden', '');
		} else {
			el.removeAttribute('hidden');
		}
	}

	function setBusy(busy) {
		if (!section) { return; }
		section.setAttribute('aria-busy', busy ? 'true' : 'false');
	}

	function setFeedback(message, kind) {
		if (!feedback) { return; }
		feedback.textContent = message || '';
		if (!message) {
			feedback.removeAttribute('data-kind');
		} else {
			feedback.setAttribute('data-kind', kind || 'info');
		}
	}

	function showSaved(masked, focusMask) {
		if (maskEl && masked) {
			maskEl.textContent = masked;
		}
		setHidden(savedView, false);
		setHidden(formView, true);
		if (input) {
			input.value = '';
		}
		if (statusEl) {
			section.setAttribute('data-state', 'saved');
		}
		if (cancelBtn) {
			setHidden(cancelBtn, false);
		}
		if (focusMask && maskEl) {
			maskEl.focus();
		}
	}

	function showForm(focusInput) {
		setHidden(savedView, true);
		setHidden(formView, false);
		section.setAttribute('data-state', 'editing');
		if (cancelBtn && maskEl && maskEl.textContent) {
			setHidden(cancelBtn, false);
		}
		if (focusInput && input) {
			input.focus();
		}
	}

	function showEmpty() {
		setHidden(savedView, true);
		setHidden(formView, false);
		if (input) {
			input.value = '';
		}
		section.setAttribute('data-state', 'empty');
		if (maskEl) {
			maskEl.textContent = '';
		}
		if (cancelBtn) {
			setHidden(cancelBtn, true);
		}
	}

	function send(action, body) {
		var payload = Object.assign({ action: action, _ajax_nonce: cfg.nonce }, body || {});
		return fetch(cfg.ajaxUrl + '?action=' + encodeURIComponent(action), {
			method: 'POST',
			credentials: 'same-origin',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json'
			},
			body: JSON.stringify(payload)
		}).then(function (res) {
			return res.json().catch(function () {
				return { success: false, data: { message: cfg.i18n.errorGeneric } };
			});
		});
	}

	function handleSave() {
		var raw = input ? input.value.trim() : '';
		if ('' === raw) {
			setFeedback(cfg.i18n.errorEmpty, 'error');
			return;
		}

		setFeedback(cfg.i18n.saving, 'info');
		setBusy(true);
		if (saveBtn) { saveBtn.disabled = true; }

		var encoded;
		try {
			encoded = btoa(raw);
		} catch (e) {
			setFeedback(cfg.i18n.errorGeneric, 'error');
			setBusy(false);
			if (saveBtn) { saveBtn.disabled = false; }
			return;
		}

		send('admin_login_sso_save_secret', { gauth_blob: encoded })
			.then(function (resp) {
				setBusy(false);
				if (saveBtn) { saveBtn.disabled = false; }
				if (resp && resp.success) {
					var msg = cfg.i18n.saved;
					var kind = 'success';
					if (resp.data && resp.data.warning) {
						msg = resp.data.warning;
						kind = 'info';
					}
					setFeedback(msg, kind);
					showSaved(resp.data && resp.data.masked ? resp.data.masked : '', true);
				} else {
					var em = (resp && resp.data && resp.data.message) ? resp.data.message : cfg.i18n.errorGeneric;
					setFeedback(em, 'error');
				}
			})
			.catch(function () {
				setBusy(false);
				if (saveBtn) { saveBtn.disabled = false; }
				setFeedback(cfg.i18n.errorGeneric, 'error');
			});
	}

	function handleClear() {
		if (!window.confirm(cfg.i18n.clearConfirm)) {
			return;
		}
		if (clearBtn) { clearBtn.disabled = true; }
		setBusy(true);
		setFeedback('', null);

		send('admin_login_sso_clear_secret', {})
			.then(function (resp) {
				setBusy(false);
				if (clearBtn) { clearBtn.disabled = false; }
				if (resp && resp.success) {
					setFeedback(cfg.i18n.cleared, 'success');
					showEmpty();
					if (input) { input.focus(); }
				} else {
					var em = (resp && resp.data && resp.data.message) ? resp.data.message : cfg.i18n.errorGeneric;
					setFeedback(em, 'error');
				}
			})
			.catch(function () {
				setBusy(false);
				if (clearBtn) { clearBtn.disabled = false; }
				setFeedback(cfg.i18n.errorGeneric, 'error');
			});
	}

	if (saveBtn)   { saveBtn.addEventListener('click', handleSave); }
	if (clearBtn)  { clearBtn.addEventListener('click', handleClear); }
	if (updateBtn) {
		updateBtn.addEventListener('click', function () {
			setFeedback('', null);
			showForm(true);
		});
	}
	if (cancelBtn) {
		cancelBtn.addEventListener('click', function () {
			setFeedback('', null);
			if (maskEl && maskEl.textContent) {
				showSaved(maskEl.textContent, false);
			} else {
				showEmpty();
			}
		});
	}
	if (input) {
		input.addEventListener('keydown', function (e) {
			if (e.key === 'Enter') {
				e.preventDefault();
				handleSave();
			}
		});
	}

	/* -----------------------------------------------------------------
	 * Copy-to-clipboard delegation
	 * Any <button data-action="copy" data-copy-target="#id"> or
	 * <button data-action="copy" data-copy-text="literal">.
	 * ----------------------------------------------------------------- */

	function showCopyToast(button) {
		var toast = button.parentNode.querySelector('.als-copy-toast');
		if (!toast) {
			toast = document.createElement('span');
			toast.className = 'als-copy-toast';
			toast.textContent = cfg.i18n.copied || 'Copied!';
			button.parentNode.insertBefore(toast, button.nextSibling);
		}
		toast.setAttribute('data-visible', 'true');
		clearTimeout(toast.__hideTimer);
		toast.__hideTimer = setTimeout(function () {
			toast.setAttribute('data-visible', 'false');
		}, 1500);
	}

	document.addEventListener('click', function (e) {
		var btn = e.target.closest('[data-action="copy"]');
		if (!btn) { return; }
		e.preventDefault();
		var text = btn.getAttribute('data-copy-text');
		if (!text) {
			var sel = btn.getAttribute('data-copy-target');
			if (sel) {
				var target = document.querySelector(sel);
				if (target) { text = target.textContent; }
			}
		}
		if (!text) { return; }
		if (navigator.clipboard && navigator.clipboard.writeText) {
			navigator.clipboard.writeText(text).then(function () {
				showCopyToast(btn);
			}).catch(function () {
				fallbackCopy(text, btn);
			});
		} else {
			fallbackCopy(text, btn);
		}
	});

	function fallbackCopy(text, btn) {
		var ta = document.createElement('textarea');
		ta.value = text;
		ta.setAttribute('readonly', '');
		ta.style.position = 'absolute';
		ta.style.left = '-9999px';
		document.body.appendChild(ta);
		ta.select();
		try {
			document.execCommand('copy');
			showCopyToast(btn);
		} catch (e) {}
		document.body.removeChild(ta);
	}

	/* -----------------------------------------------------------------
	 * Domain chip preview
	 * ----------------------------------------------------------------- */

	var domainRe = /^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

	function renderChipPreview(textarea) {
		var key = textarea.id || textarea.name;
		var holder = key ? document.querySelector('div.als-chip-preview[data-chip-preview-for="' + key + '"]') : null;
		if (!holder) { return; }
		holder.innerHTML = '';
		var raw = textarea.value || '';
		var parts = raw.split(',').map(function (s) { return s.trim().toLowerCase(); }).filter(Boolean);
		var seen = {};
		parts.forEach(function (d) {
			if (seen[d]) { return; }
			seen[d] = true;
			var chip = document.createElement('span');
			chip.className = 'als-chip';
			if (d.indexOf('*.') === 0) { chip.className += ' als-chip--wildcard'; }
			if (!domainRe.test(d))     { chip.className += ' als-chip--invalid'; }
			chip.textContent = d;
			holder.appendChild(chip);
		});
	}

	document.querySelectorAll('[data-action="domain-preview"]').forEach(function (ta) {
		renderChipPreview(ta);
		ta.addEventListener('input', function () { renderChipPreview(ta); });
	});

	/* -----------------------------------------------------------------
	 * Client ID format validator
	 * ----------------------------------------------------------------- */

	var clientIdRe = /^[\w-]+\.apps\.googleusercontent\.com$/;

	document.addEventListener('click', function (e) {
		var btn = e.target.closest('[data-action="validate-client-id"]');
		if (!btn) { return; }
		e.preventDefault();
		var field = byId('admin_login_sso_client_id');
		var feedbackEl = document.querySelector('[data-feedback-for="admin_login_sso_client_id"]');
		if (!field || !feedbackEl) { return; }
		var v = (field.value || '').trim();
		if (!v) {
			feedbackEl.setAttribute('data-kind', 'warning');
			feedbackEl.innerHTML = '<span class="dashicons dashicons-info"></span> ' + escapeHtml(cfg.i18n.cidEmpty || 'Enter a Client ID to check.');
			return;
		}
		if (clientIdRe.test(v)) {
			feedbackEl.setAttribute('data-kind', 'success');
			feedbackEl.innerHTML = '<span class="dashicons dashicons-yes-alt"></span> ' + escapeHtml(cfg.i18n.cidOk || 'Format looks valid.');
		} else {
			feedbackEl.setAttribute('data-kind', 'error');
			feedbackEl.innerHTML = '<span class="dashicons dashicons-warning"></span> ' + escapeHtml(cfg.i18n.cidBad || 'Expected a value ending in .apps.googleusercontent.com');
		}
	});

	function escapeHtml(s) {
		return String(s).replace(/[&<>"']/g, function (c) {
			return {
				'&': '&amp;',
				'<': '&lt;',
				'>': '&gt;',
				'"': '&quot;',
				"'": '&#39;'
			}[c];
		});
	}
})();
