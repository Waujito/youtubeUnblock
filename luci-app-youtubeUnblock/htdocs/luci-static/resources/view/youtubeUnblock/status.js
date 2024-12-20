'use strict';
'require view';
'require poll';
'require fs';
'require ui';
'require uci';
'require form';
'require tools.widgets as widgets';
'require tools.views as views';

/**
 * Big thanks to luci-app-adblock for the best reference implementation
 */


/*
	button handling
*/
function handleAction(act, event) {
	if (event.target.classList.contains('disabled') || event.target.classList.contains('cbi-button-inactive'))
		return;

	function roll_inact(target) {
		target.classList.add('spinning');	
		target.classList.add('disabled');	
	}
	function unroll_inact(target) {
		target.classList.remove('spinning');	
		target.classList.remove('disabled');	
	}
	function thn_disp() {
		unroll_inact(event.target);
	}
	function thn_inc() {
		roll_inact(event.target);
	}

	roll_inact(event.target);
	if (act == "restart") {
		fs.exec_direct('/etc/init.d/youtubeUnblock', [ 'restart' ]).then(thn_disp);
	} else if (act == "fw_reload") {
		fs.exec_direct('/etc/init.d/firewall', [ 'reload' ]).then(thn_disp);
	} else if (act == "status") {
		if (event.target.classList.contains('cbi-button-positive')) {
			fs.exec_direct('/etc/init.d/youtubeUnblock', [ 'start' ]).then(thn_inc);
		} else {
			fs.exec_direct('/etc/init.d/youtubeUnblock', [ 'stop' ]).then(thn_inc);
		}
	} else if (act == "autostart") {
		if (event.target.classList.contains('cbi-button-positive')) {
			fs.exec_direct('/etc/init.d/youtubeUnblock', [ 'enable' ]).then(thn_inc);
		} else {
			fs.exec_direct('/etc/init.d/youtubeUnblock', [ 'disable' ]).then(thn_inc);
		}
	} else {
		unroll_inact(event.target);
	}

}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('youtubeUnblock'),
		]);
	},

	render: function(result) {
		let m, s, o;
"youtubeUnblock", "youtubeUnblock", "Bypasses Deep Packet Inspection (DPI) systems that rely on SNI"
		m = new form.Map('youtubeUnblock', 'youtubeUnblock', _("Bypasses Deep Packet Inspection (DPI) systems that rely on SNI. <br />	Check the README for more details <a href=\"https://github.com/Waujito/youtubeUnblock\">https://github.com/Waujito/youtubeUnblock</a>"));

		/*
			poll runtime information
		*/
		pollData: poll.add(function() {
			fs.exec_direct('/etc/init.d/youtubeUnblock', ['status'])
			.then(function(res) {
				const status = document.getElementById('ytb_status');
				const btn_status = document.getElementById('btn_status');
				if (status == null || btn_status == null) {
					return;
				}

				status.classList.remove("spinning");
				res = res.trim();
				status.textContent = res;

				if (res != "inactive" && res != "running") {
					return;
				}

				btn_status.classList.remove("spinning");
				btn_status.classList.remove("cbi-button-inactive");
				btn_status.classList.remove("cbi-button-negative");
				btn_status.classList.remove("cbi-button-positive");
				btn_status.classList.remove("disabled");


				if (res == "running") {
					btn_status.textContent = "Stop";
					btn_status.classList.add("cbi-button-negative");
				} else {
					btn_status.textContent = "Start";
					btn_status.classList.add("cbi-button-positive");
				}
			});

			fs.exec_direct('/usr/bin/youtubeUnblock', ['--version'])
			.then(function(res) {
				const elversion = document.getElementById('ytb_version');
				if (elversion == null) {
					return;
				}

				elversion.classList.remove("spinning");

				elversion.textContent = res;
			});

			fs.exec('/etc/init.d/youtubeUnblock', ['enabled'])
			.then(function(res) {
				const autostart = document.getElementById('ytb_autostart');
				const btn_autostart = document.getElementById('btn_autostart');
				if (autostart == null || btn_autostart == null) {
					return;
				}

				autostart.classList.remove("spinning");

				btn_autostart.classList.remove("spinning");
				btn_autostart.classList.remove("cbi-button-inactive");
				btn_autostart.classList.remove("cbi-button-negative");
				btn_autostart.classList.remove("cbi-button-positive");
				btn_autostart.classList.remove("disabled");

				if (res.code == 0) {
					autostart.textContent = "enabled";
					btn_autostart.textContent = "Disable";
					btn_autostart.classList.add("cbi-button-negative");
				} else {
					autostart.textContent = "disabled";
					btn_autostart.textContent = "Enable";
					btn_autostart.classList.add("cbi-button-positive");
				}
			});

			fs.exec_direct("/sbin/logread", ['-e', "youtubeUnblock", '-l', 200]).then(function(res) {
				const log = document.getElementById("ytb_logger");
				if (log == null) 
					return;

				if (res) {
					log.value = res.trim();
				} else {
					log.value = _('No related logs yet!');
				}
				log.scrollTop = log.scrollHeight;
			});

		}, 1);

		/*
			runtime information and buttons
		*/
		s = m.section(form.NamedSection, 'global');
		s.render = L.bind(function(view, section_id) {
			return E('div', { 'class': 'cbi-section' }, [
				E('h3', _('Information')), 
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title', 'style': 'padding-top:0rem' }, _('Version')),
					E('div', { 'class': 'cbi-value-field spinning', 'id': 'ytb_version', 'style': 'color:#37c' },'\xa0')
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title', 'style': 'padding-top:0rem' }, _('Status')),
					E('div', { 'class': 'cbi-value-field spinning', 'id': 'ytb_status', 'style': 'color:#37c' },'\xa0')
				]),
				E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title', 'style': 'padding-top:0rem' }, _('Autostart')),
					E('div', { 'class': 'cbi-value-field spinning', 'id': 'ytb_autostart', 'style': 'color:#37c' },'\xa0')
				]),
				E('div', { class: 'right' }, [
					E('button', {
						'class': 'btn cbi-button cbi-button-inactive disabled spinning',
						'id': 'btn_autostart',
						'click': ui.createHandlerFn(this, function(event) {
							return handleAction('autostart', event);
						})
					}, [ _('Autostart') ]),
					'\xa0\xa0\xa0',
					E('button', {
						'class': 'btn cbi-button cbi-button-inactive disabled spinning',
						'id': 'btn_status',
						'click': ui.createHandlerFn(this, function(event) {
							return handleAction('status', event);
						})
					}, [ _('Status') ]),
					'\xa0\xa0\xa0',
					E('button', {
						'class': 'btn cbi-button cbi-button-apply',
						'click': ui.createHandlerFn(this, function(event) {
							return handleAction('restart', event);
						})
					}, [ _('Restart') ]),
					'\xa0\xa0\xa0',
					E('button', {
						'class': 'btn cbi-button cbi-button-apply',
						'id': 'btn_fw_reload',
						'click': ui.createHandlerFn(this, function(event) {
							return handleAction('fw_reload', event);
						})
					}, [ _('Firewall reload') ]),
				])
			]);
		}, o, this);

		const logs_s = m.section(form.NamedSection, 'ytb_logs');
		logs_s.render = L.bind(function(view, section_id) {
			return E('div', { class: 'cbi-map' },
				E('div', { class: 'cbi-section' }, [
				E('div', { class: 'cbi-section-descr' }, _('The syslog output, pre-filtered for messages related to: youtubeUnblock')),
				E('textarea', {
					'id': 'ytb_logger',
					'style': 'width: 100% !important; padding: 5px; font-family: monospace',
					'readonly': 'readonly',
					'wrap': 'off',
					'rows': 25
				})
			]));
		});
		this.pollData;

		return m.render();
	},
	handleReset: null,
	handleSaveApply: null,
	handleSave: null,
});

