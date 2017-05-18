# gitlab-importer
import data form other version gitlab。

### Usage
run `python /this/a/app/path/gitlab-importer/main.py`, gitlab-importer will read `Workingdir/conf/setting.yml` config file.

### Settings
[sample_setting.yml](gitlab-importer/conf/sample_setting.yml)。
config:

 - source/dest, host/dest.
 - new_user_password，auto create use will use this password.
 - send_email, send email guide user rest password email.
