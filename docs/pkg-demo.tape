# vhs tape for docs/pkg-demo.gif  (https://github.com/charmbracelet/vhs)
# Pre-install vetting: a typo'd package name that is actually squatted
# malware (real MAL advisory), then a deprecated+vulnerable classic.

Output pkg-demo.gif

Set FontSize 15
Set Width 1000
Set Height 460
Set Padding 12
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set Shell "bash"

Type "# about to add a dependency? vet it before you install:"
Enter
Sleep 800ms
Type "lockvet pkg npm:chakl"
Enter
Sleep 3s
Type "# (you meant chalk — and that typo is squatted malware.)"
Enter
Sleep 1500ms
Type "lockvet pkg npm:request"
Enter
Sleep 4s
Sleep 4s
