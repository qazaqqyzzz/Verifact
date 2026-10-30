#!/bin/zsh
# Open this file to start Verifact on your Mac.
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
