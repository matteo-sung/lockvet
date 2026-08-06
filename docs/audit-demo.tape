# vhs tape for docs/audit-demo.gif  (https://github.com/charmbracelet/vhs)
# Sweeps a tree that already pins malicious versions from two real
# incidents (Shai-Hulud npm carriers + ultralytics PyPI miner).
# Fixture matches docs/case-studies.md §7.

Output audit-demo.gif

Set FontSize 15
Set Width 1000
Set Height 580
Set Padding 12
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set Shell "bash"

Hide
Type `rm -rf /tmp/audit-demo && mkdir -p /tmp/audit-demo/web /tmp/audit-demo/api && cd /tmp/audit-demo && printf '%s' '{"name":"web","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"web","version":"1.0.0","dependencies":{"@ctrl/tinycolor":"^4.1.0","chalk":"^5.6.0"}},"node_modules/@ctrl/tinycolor":{"version":"4.1.1","resolved":"https://registry.npmjs.org/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz"},"node_modules/chalk":{"version":"5.6.1","resolved":"https://registry.npmjs.org/chalk/-/chalk-5.6.1.tgz"}}}' > web/package-lock.json && printf 'ultralytics==8.3.41\n' > api/requirements.txt && clear`
Enter
Show

Type "# news breaks: chalk, @ctrl/tinycolor, ultralytics compromised."
Enter
Sleep 1s
Type "# are we already carrying any of it? sweep the whole tree:"
Enter
Sleep 1s
Type "lockvet audit ."
Enter
Sleep 8s
Sleep 4s
