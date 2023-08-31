# emlx\_to\_mbox

## Introduction

Apple **Mail.app** allows users to export mailboxes to .mbox format. However,
as of macOS Sierra, this feature is broken, especially when the distant account
is offline: messages with attachments that were extracted by Mail are not
recovered.

With macOS Ventura, the feature works much better but may occasionnaly fail.

This is not new. Several tools exist to convert messages from Apple Mail's
proprietary format to open source formats. The most well known are:

 * Mike Laiosa's [open source Python script](https://github.com/mlaiosa/emlx2maildir)
   to convert mailboxes to Maildir format and [its fork](https://github.com/pascalrobert/emlx2maildir)
   by Pascal Robert
 * cosmicsoft's [binary application](http://www.cosmicsoft.net/emlxconvert.html)
   to convert mailboxes to mbox format
 * Philip Katz more recent [open source NodeJS script](https://github.com/qqilihq/partial-emlx-converter)
   to convert mailboxes to elm format

At the time of this writing, the first two were not updated for macOS Sierra format, and are especially not able
to properly recover attachments. The third can fail on some attachment that this script is able to recover.

This script, written in Erlang, will convert a mailbox into mbox format ([dovecot
variant](https://wiki.dovecot.org/MailboxFormat/mbox)) by using known flags to
record each message status and by reencoding attachments.

## Features

``emlx_to_mbox`` features include:

 * Handling both V4 (macOS Sierra) and V3 formats
 * Checking every mail and generating a warning for mails with missing
   attachment(s)
 * Filtering duplicates with identical remote-ids, favoring duplicates with
   attachments (happening with V3 format)
 * Generating dovecot status headers corresponding to emlx flags
   (Read/Answered/Forwared/Junk/etc.)
 * When attachments could not be found in ../Attachments/, searching harder with
   Spotlight in ``~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads``
   where Mail saves opened attachments and picking up the first attachment with
   a matching name. The script will generate a warning as it might not be the
   proper file.
 * Re-zipping attachments that were unzipped.

## Usage:

 * Install [Erlang/OTP](http://www.erlang.org).

 * Run:

 ``escript emlx_to_mbox.escript ~/Library/Mail/V4/UUID/Mailbox.mbox -o ~/Desktop/MailboxConverted.mbox``

 * You can also test the script on a single message with:
 
 ``escript emlx_to_mbox.escript --single ~/Library/Mail/V4/UUID/Mailbox.mbox/Path/To/ID.emlx``

## Known bugs and limitations:

 * The messages are appended at every run.
 * Attachments in ~/Library/Mail\ Downloads/ with names that are UTF-8 composed
   differently from their name in the Content-Disposition header are not found.
 * Very long filenames will not be parsed propermy.
 * Every emlx message in the mailbox will be appended, and therefore sub-mailboxes
   require special care.

## Miscellanae

This bug in Mail.app was reported to Apple as radr://34076819

emlx format flags were [collected by jwz](https://www.jwz.org/blog/2005/07/emlx-flags/).
In 10.12 and 10.11, additional flags (beyond 32 bits) were observed.

It seems that macOS Sierra Mail.app does not track the link between opened
attachments in ``~/Library/Mail\ Downloads/`` and their message, which could
explain why these attachments are often duplicated. Previous versions tracked
them in ``~/Library/Mail/V4/MailData/OpenedAttachmentsV2.plist``.
