# vhs tape for docs/supplychain-demo.gif  (https://github.com/charmbracelet/vhs)
# Replays the Sept 2025 chalk+debug npm takeover during its 2-hour live window
# (before any advisory existed). Fixture matches docs/case-studies.md §3.

Output supplychain-demo.gif

Set FontSize 15
Set Width 940
Set Height 420
Set Padding 12
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set Shell "bash"

Hide
Type `rm -rf /tmp/sc-demo && mkdir -p /tmp/sc-demo/old /tmp/sc-demo/new && cd /tmp/sc-demo && printf '%s' '{"name":"my-app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"my-app","version":"1.0.0","dependencies":{"chalk":"^5.6.0","debug":"^4.4.1"}},"node_modules/chalk":{"version":"5.6.0","resolved":"https://registry.npmjs.org/chalk/-/chalk-5.6.0.tgz"},"node_modules/debug":{"version":"4.4.1","resolved":"https://registry.npmjs.org/debug/-/debug-4.4.1.tgz","dependencies":{"ms":"^2.1.3"}},"node_modules/ms":{"version":"2.1.3","resolved":"https://registry.npmjs.org/ms/-/ms-2.1.3.tgz"}}}' > old/package-lock.json && sed 's/5\.6\.0/5.6.1/g; s/4\.4\.1/4.4.2/g' old/package-lock.json > new/package-lock.json && clear`
Enter
Show

Type "# Sept 8 2025: chalk & debug hijacked on npm. Advisory came a WEEK later."
Enter
Sleep 1s
Type "# replay the exact bump, during the 2-hour attack window:"
Enter
Sleep 1s
Type "lockvet diff old/package-lock.json new/package-lock.json"
Enter
Sleep 7s
Sleep 4s
