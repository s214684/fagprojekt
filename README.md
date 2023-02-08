# fagprojekt



## Areas of responsibility

### Code-manager
Mediater in code-reviews, keep overview of the whole codebase, make sure styleguiide is followed.

Oliver Tabersen


### Report-/hand-in-manager
Keep the report "up-to-date", Making sure we follow deadlines, spellcheck

Lucas Tabersen


### Project-manager
kanbas board, calendar meetings, github issues, referat, update project description

Nicklas Tabersen


### Communication manager

Lucas Tabersen



## Code style guideline 
- Everything on github has to be in English.
- We structure our code by the PEP8 standards. 
- One can only say a function/code is done/ready after code-review.

### Linting
use flake8
Ignore E501 (we don't care about long lines..)

add following to your settings file in vs code:

"python.linting.flake8Enabled": true,
"python.linting.mypyEnabled": true,
"python.linting.flake8Args": ["--ignore=E501"]

such that it is inside the outermost {}!