
## Script for managing github pull request comments.

This python3 program scans your open github pull request submissions (PR's) and notifies you if there were new/modified or deleted PR comments. This script is for people like me who didn't manage to configure github notifications - there is always too many or to few of them.

### Usage

The program scans the github repositories of a particular user once every fifteen minutes (by default).
It writes an HTML report and pops it up in the default web browser if any PR comments were modified/added/deleted.

By default it asks for the github token in an interactive password prompt, however you can set the gigithub token in an environment variable.

By default the program scans your github account once every fifteen minutes.

The program has some command line options, here is the story:

```
Usage: periodically checks your github PR's for new comments.
Uses the github api for the check.
During every check it checks if any comments were added/removed/modified in the PR (relative to the last check). If changes were detected then a report is displayed in the default web browser.

The first iteration will give you a full list of all prs, subsequent iterations will give you the diff by comparing the comments against the serialized state of the last check.

The program asks for the github token in a password prompt (can also pass via env. variable)


Options:
  -h, --help            show this help message and exit
  -t SLEEP_TIME_MINUTES, --time=SLEEP_TIME_MINUTES
                        Check for changes every num miminutes
  -s DB_FILE_NAME, --source=DB_FILE_NAME
                        change default db file for storing current github
                        state
  -r REPORT_FILE, --report=REPORT_FILE
                        path of html report output file
  -p, --passenv         if pass github token via env. variable GITHUB_TOKEN,
                        defaults to prompt.
  -d, --debug           turn on tracing of script
  -q, --quiet           ignore comments made by me, only notify on comments
                        made by others

```

### Installation 

This program uses the [PyGithub api](https://pygithub.readthedocs.io/en/latest/reference.html)

to install that requirement:

````
sudo pip3 install PyGitHub
````

Now you should be ready to run the script in this repository.


### what can be improved?

I tried to used googleapi in order to send emails to myself, but that didn't work out.
Anyway, poping up a report in the current browser is good enough for me.

### what I learned from all this

i didn't learn too much in terms of technology, more in the area of sociology: as part of the coronavirus crisis most companies started remote work/ work from home, Now my naive hope would be that office politics would be less pronounced and have less of a chance; but reality seems to be different and there is always to we to continue the show with other means. Sad.


