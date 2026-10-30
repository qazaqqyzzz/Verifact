#!/bin/zsh
# Compatibility launcher. New installations can use Start Verifact.command.
cd -- "${0:A:h}" || exit 1
if [[ -x .venv/bin/python ]]; then
  .venv/bin/python -m verify serve --open
else
  python3 -m verify serve --open
fi
if [[ $? -ne 0 ]]; then
  print "Verifact could not start. Check the message above."
  read "?Press Enter to close."
fi
