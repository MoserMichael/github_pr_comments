
## Script for managing github pull request comments.

This python3 program scans your github pull requests (PR's) and notifies you if there were new or modified PR comments (that one is for people like me who didn't manage to configure gitbub notifications - there is always too many or to few of them).

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

```

### Installation 

This program uses the [PyGithub api](https://pygithub.readthedocs.io/en/latest/reference.html)

install it as follows:

````
sudo pip3 install PyGitHub
````

otherwise it uses plain python3.


### what can be improved?

I tried to used googleapi in order to send emails to myself, but that didn't work out.
Anyway, poping up a report in the current browser is good enough for me.


