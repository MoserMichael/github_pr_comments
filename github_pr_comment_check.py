#!/usr/bin/python3
import getpass
import pickle
import datetime
import logging
import time
import sys
import os.path
import webbrowser
import optparse

from github import Github

#import base64
#from email.mime.text import MIMEText
#from googleapiclient.discovery import build
#from google_auth_oauthlib.flow import InstalledAppFlow
#from google.auth.transport.requests import Request
#from googleapiclient.errors import HttpError

STATUS_NEW = 0
STATUS_NOTMODIFIED = 1
STATUS_DELETED = 2
STATUS_MODIFIED = 3

class OpenHtmlInBrowser:
    def __init__(self, file_name):
        self.set_file(file_name)

    def set_file(self, file_name):
        self.file_name = file_name

    def notify(self, message_text):

        ofile = open(self.file_name, "w")

        msg = '<html><head><title>PR comments on {}</title></head><body>'.\
                format(datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"))

        ofile.write(msg)
        ofile.write(message_text)
        ofile.close()

        webbrowser.open_new_tab("file://{}".format(self.file_name))



#class GmailClientLibrary:
#    def __init__(self):
#        creds = None
#        # The file token.pickle stores the user's access and refresh tokens, and is
#        # created automatically when the authorization flow completes for the first
#        # time.
#        if os.path.exists('token.pickle'):
#            with open('token.pickle', 'rb') as pickle_token:
#                creds = pickle.load(pickle_token)
#        # If there are no (valid) credentials available, let the user log in.
#        if not creds or not creds.valid:
#            if creds and creds.expired and creds.refresh_token:
#                creds.refresh(Request())
#            else:
#                flow = InstalledAppFlow.from_client_secrets_file(
#                    './credentials.json', SCOPES)
#                creds = flow.run_local_server(port=0)
#            # Save the credentials for the next run
#            with open('token.pickle', 'wb') as pickle_token:
#                pickle.dump(creds, pickle_token)
#
#        self.service = build('gmail', 'v1', credentials=creds)
#
#        users = self.service.users()
#
#        profile = users.getProfile(userId='me')
#
#        myprofile = profile.execute()
#
#        self.my_email = myprofile['emailAddress']
#
#
#
#    def notify(self, message_text):
#        EMAIL_SUBJECT = "github change in comments on submitted PR's"
#        # If modifying these scopes, delete the file token.pickle.
#        SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
#
##
##        message = MIMEText(message_text, 'html')
##        message['to'] = self.my_email
##        message['from'] = self.my_email
##        message['subject'] = subject
##
##        emessage = {'raw': base64.urlsafe_b64encode(message.as_string())}
##
#        subject = EMAIL_SUBJECT
#        try:
#            message = (self.service.users().messages().send(userId='me', body=message_text)
#                       .execute())
#            print('Message Id: %s' % message['id'])
#            return message
#        except HttpError as error:
#            print('An error occurred while sending the mail: %s' % error)
#

class EntryBaseDB:
    def  __init__(self, scan_number=-1):
        self.status = STATUS_NEW
        self.scan_number = scan_number

    def set_scan_number(self, scan_number, status):
        self.status = status
        self.scan_number = scan_number

    def mark_deleted(self, scan_number):
        if self.scan_number < scan_number:
            self.status = STATUS_DELETED

class CommentDB(EntryBaseDB):
    def __init__(self, github_comment, scan_number):
        super().__init__(scan_number)
        self.comment_id = github_comment.id
        self.body = github_comment.body
        self.url = github_comment.html_url
        self.user = github_comment.user
        self.created_at = github_comment.created_at
        logging.info("\t\t\tnew comment id %s url %s body %s", self.comment_id, self.url, self.body)

    def diff_report(self, msg, ignore_comments_by_user):
        if self.status == STATUS_NOTMODIFIED:
            return ""

        if ignore_comments_by_user is not None and self.user.login == ignore_comments_by_user:
            return ""

        report = msg + '&nbsp;<a href="{}">by {} [LINK TO COMMENT]</a> on {}'.\
               format(self.url, self.user.login, self.created_at)

        if self.status == STATUS_NEW:
            report += "&nbsp;[new comment]\n"
        elif self.status == STATUS_DELETED:
            report += "&nbsp;[deleted comment]\n"
        else:
            report += "&nbsp;[modified comment]\n"

        report += '<pre>{}</pre>'.format(self.body)

        return report

class PullDB(EntryBaseDB):
    def __init__(self, github_pull, scan_number):
        super().__init__(scan_number)
        self.comments = []
        self.pull_id = github_pull.id
        self.number = github_pull.number
        self.title = github_pull.title
        self.url = github_pull.html_url #review_comment_url


    def find_or_create_comment(self, github_comment, scan_number):
        for comment in self.comments:
            if comment.comment_id == github_comment.id:
                modified = STATUS_NOTMODIFIED
                if comment.body != github_comment.body:
                    modified = STATUS_MODIFIED
                    comment.body = github_comment.body
                    logging.info("\t\t\tmodified comment id %s url %s body %s",\
                            comment.comment_id, comment.url, comment.body)
                else:
                    logging.info("\t\t\tcomment id %d {}", \
                            comment.comment_id)

                comment.set_scan_number(scan_number, modified)
                return comment
        comment = CommentDB(github_comment, scan_number)
        self.comments.append(comment)
        return comment

    def mark_deleted(self, scan_number):
        super().mark_deleted(scan_number)
        for comment in self.comments:
            comment.mark_deleted(scan_number)


    def remove_deleted(self):
        for comment in self.comments:
            if comment.status == STATUS_DELETED:
                self.comments.remove(comment)

    def diff_report(self, msg, ignore_comments_by_user):
        msg += 'pull request <a href="{}">#{} {}<a>&nbsp;'.\
                    format(self.url, self.number, self.title)
        if self.status == STATUS_NEW:
            msg += "[New PR]&nbsp;"
        if self.status == STATUS_DELETED:
            msg += "[PR No longer open]&nbsp;"


        report = ""
        for comment in self.comments:
            report += comment.diff_report(msg, ignore_comments_by_user)

        return report

class RepoDB(EntryBaseDB):
    def __init__(self, github_repo, scan_number):
        super().__init__(scan_number)
        self.pulls = []
        self.repo_name = github_repo.name
        self.url = github_repo.html_url

    def find_or_create_pull(self, github_pull, scan_number):
        for pull in self.pulls:
            if pull.pull_id == github_pull.id:
                pull.set_scan_number(scan_number, STATUS_NOTMODIFIED)
                return pull
        pull = PullDB(github_pull, scan_number)
        self.pulls.append(pull)
        return pull

    def mark_deleted(self, scan_number):
        super().mark_deleted(scan_number)
        for pull in self.pulls:
            pull.mark_deleted(scan_number)

    def remove_deleted(self):
        for pull in self.pulls:
            if pull.status == STATUS_DELETED:
                self.pulls.remove(pull)
            else:
                pull.remove_deleted()

    def diff_report(self, ignore_comments_by_user):
        msg = '<hr>repo: <a href="{}">{}</a>&nbsp;'.format(self.url, self.repo_name)

        report = ""
        for pull in self.pulls:
            report += pull.diff_report(msg, ignore_comments_by_user)

        return report


class UserDB:
    def __init__(self, file_name):
        super().__init__()
        self.repos = []
        self.file_name = file_name

    def find_or_create_repo(self, github_repo, scan_number):
        for repo in self.repos:
            if repo.repo_name == github_repo.name:
                repo.set_scan_number(scan_number, STATUS_NOTMODIFIED)
                return repo
        repo = RepoDB(github_repo, scan_number)
        self.repos.append(repo)
        return repo

    def mark_deleted(self, scan_number):
        for repo in self.repos:
            repo.mark_deleted(scan_number)


    def remove_deleted(self):
        for repo in self.repos:
            if repo.status == STATUS_DELETED:
                self.repos.remove(repo)
            else:
                repo.remove_deleted()


    def load(self):
        if os.path.isfile(self.file_name):
            pickle_in = open(self.file_name, "rb")
            for _ in range(pickle.load(pickle_in)):
                self.repos.append(pickle.load(pickle_in))
            pickle_in.close()

    def save(self):
        pickle_out = open(self.file_name, "wb")
        pickle.dump(len(self.repos), pickle_out)
        for repo in self.repos:
            pickle.dump(repo, pickle_out)
        pickle_out.close()

    def diff_report(self, ignore_comments_by_user):
        report = ""
        for repo in self.repos:
            report += repo.diff_report(ignore_comments_by_user)

        return report



class Lister:
    def __init__(self, user_db, access_token, ignore_my_comments):
        super().__init__()
        self.user = None
        self.user_db = user_db
        self.scan_number = 1
        self.access_token = access_token
        self.ignore_my_comments = ignore_my_comments
        self.ignore_comments_by_user = None

    def scan_repos(self):
        self.scan_number += 1

        github = Github(login_or_token="access_token", password=self.access_token)
        self.user = github.get_user()
        if self.ignore_my_comments:
            self.ignore_comments_by_user = self.user.login

        for repo in self.user.get_repos():

            # PRs only submitted on forked repos (that start with user prefix)
            if not repo.full_name.startswith(self.user.login):
                continue
            if not repo.fork:
                continue

            logging.info("\trepo: %s", repo.name)
            repo_obj = self.user_db.find_or_create_repo(repo, self.scan_number)
            self.scan_repo_open_pulls(repo, repo_obj)

        # mark all not visited entries as deleted.
        self.user_db.mark_deleted(self.scan_number)

        # make the report
        report = self.user_db.diff_report(self.ignore_comments_by_user)

        # remove elements marked for deletion
        self.user_db.remove_deleted()

        # save the db
        self.user_db.save()

        return report

    def scan_repo_open_pulls(self, repo, repo_obj):
        pulls = repo.parent.get_pulls(state='open', sort='created')
        for pull in pulls:
            if pull.user.login == self.user.login:
                logging.info("\t\tpull id %s title %s url %s",\
                        pull.id, pull.title, pull.review_comment_url)
                pull_obj = repo_obj.find_or_create_pull(pull, self.scan_number)
                self.scan_comments(pull, pull_obj)

    def scan_comments(self, pull, pull_obj):
        lst = pull.get_review_comments()
        for comment in lst:
            pull_obj.find_or_create_comment(comment, self.scan_number)

class Loop:
    def __init__(self, db_file_name, ignore_my_comments):
        self.init_db(db_file_name)
        self.ignore_my_comments = ignore_my_comments

    def init_db(self, db_file_name):
        self.user_db = UserDB(db_file_name)

    def scan_and_notify(self, github_access_token, notifier, sleep_time_in_minutes):
        self.user_db.load()

        lst = Lister(self.user_db, github_access_token, self.ignore_my_comments)

        while True:
            try:
                report = lst.scan_repos()
                if report != "":
                    logging.info("changes in PR comments - new report here")
                    notifier.notify(report)
                else:
                    logging.info("no changes in PR comments detected")
            except:
                print("error happened: ", sys.exc_info()[0])
            time.sleep(60 * sleep_time_in_minutes)


#---

def set_info_logger():
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    file_handler = logging.FileHandler("gh.log")
    root.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    root.addHandler(console_handler)

def parse_args():
    usage = '''periodically checks your github PR's for new comments.
Uses the github api for the check.
During every check it checks if any comments were added/removed/modified in the PR (relative to the last check). If changes were detected then a report is displayed in the default web browser.

The first iteration will give you a full list of all prs, subsequent iterations will give you the diff by comparing the comments against the serialized state of the last check.

The program asks for the github token in a password prompt (can also pass via env. variable)
'''

    parser = optparse.OptionParser(usage=usage)

    parser.add_option('-t', '--time', type='int', dest='SLEEP_TIME_MINUTES',\
                default=15, \
                help='Check for changes every num miminutes')
    parser.add_option('-s', '--source', type='string', dest='DB_FILE_NAME',\
            default=os.path.expanduser("~/.github-notify-db"), \
            help='change default db file for storing current github state')
    parser.add_option('-r', '--report', type='string', dest='REPORT_FILE',\
            default=os.path.expanduser("~/.github-notify-outfile.html"), \
            help='path of html report output file')
    parser.add_option('-p', '--passenv', dest='PASS_TOKEN_ENV', action='store_true',\
            default=False, \
            help='if pass github token via env. variable GITHUB_TOKEN, defaults to prompt.')
    parser.add_option('-d', '--debug', dest='DEBUG_ON', action='store_true',\
            default=False, \
            help='turn on tracing of script')
    parser.add_option('-q', '--quiet', dest='QUIET', action='store_true',\
            default=False, \
            help='ignore comments made by me, only notify on comments made by others')

    (options, _) = parser.parse_args(sys.argv[1:])

#    print("QUIET {} SLEEP_TIME_MINUTES {} DB_FILE_NAME {} REPORT {}"\
#           "DEBUG_ON {} PASS_TOKEN_ENV {}".\
#            format(options.QUIET, options.SLEEP_TIME_MINUTES, options.DB_FILE_NAME,
#                   optiont.REPORT_FILE, options.DEBUG_ON, options.PASS_TOKEN_ENV))
#
    return options

def main():

    options = parse_args()

    if options.DEBUG_ON:
        set_info_logger()

    if options.PASS_TOKEN_ENV:
        # don't know how to remove that from /proc in python. fun.
        token = os.environ['GITHUB_TOKEN']
    else:
        token = getpass.getpass("enter github token: ")
        token = token.rstrip()

    #notify = GmailClientLibrary()
    notify = OpenHtmlInBrowser(options.REPORT_FILE)

    loop = Loop(options.DB_FILE_NAME, options.QUIET)
    loop.scan_and_notify(token, notify, options.SLEEP_TIME_MINUTES)


if __name__ == '__main__':
    main()
